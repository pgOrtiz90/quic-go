package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"math/rand"
	"bytes"
	"github.com/lucas-clemente/quic-go/traces"
)

type FecDecoder struct{
	Id				uint64
	Ratio			uint8
	Count 		uint8
	lastForwarded uint8
	lastPacketNumberForwarded protocol.PacketNumber
	storedPackets     []*receivedPacket
	unforwardedPackets []*receivedPacket
	MaxLength protocol.ByteCount
	hdr			*wire.Header

	randomNumber	uint8

	trace   *FecTracer;
}


type FecTracer struct{
		decoded uint
		blocks uint
		failure uint
		redundant uint
}

//Store received packets
func (f *FecDecoder) HandlePacket2(p *receivedPacket) (int, []*receivedPacket){
	//fmt.Printf("Handle PAckets: Type: %d, Count: %d\n", p.header.FecType, p.header.FecCount)

	if (f.Id == 0 && f.Count== 0){
		traces := &FecTracer{}
		f.trace = traces
	}

	var r_packets []*receivedPacket

	if p.header.FecType & (0x80) == 0x00{
		utils.DebugfFEC("FEC - Packet not protected\n")
		if (p.header.PacketNumber > f.lastPacketNumberForwarded && len(f.unforwardedPackets) >  0) {
			f.unforwardedPackets = append(f.unforwardedPackets,p)
			return 0,nil
		}else{
			r_packets = append(r_packets, p)
			return len(r_packets), r_packets
		}
	}

	/*
	//Some fake losses
	if (0.1 >= rand.Float64()){
		utils.DebugfFEC("Packet PN: %d discarted!!", p.header.PacketNumber)

		//fmt.Printf("Packet PN: %d discarted!!", p.header.PacketNumber)
		fmt.Printf("Packet PN: %d DISCARTED!!, Ratio: %d,  Count: %d, Len: %d \n", p.header.PacketNumber, p.header.FecRatio, p.header.FecCount, len(p.data))

		if (p.header.FecType & (0xC0)) == 0xC0{
			fmt.Printf("FEC DISCARTED %d, %d, %d \n", p.header.PacketNumber, f.Ratio, f.Count)
		}
		return len(r_packets), r_packets
	}
	*/


	Id := f.GetFecId(p.header.FecId)

	if ( Id < f.Id) {
		utils.DebugfFEC("Received Packet from previous block \n")
		return  len(r_packets), r_packets
	}

	if (Id > f.Id){
		r_packets = append(r_packets, f.unforwardedPackets...)

		//fmt.Printf("Previous Block: %d, %d, %d\n", f.Id, f.Ratio, f.Count)
		if (f.Count > f.Ratio){
			//utils.DebugfFEC("Previous FEC block fails \n")
			//fmt.Printf("Decoding Failure REDUNDANT - ID: %d Count: %d Ratio:%d \n", f.Id, f.Count, f.Ratio)
			f.trace.redundant += 1
			f.trace.blocks +=1
		}else if (f.Count < f.Ratio -1){
			//fmt.Printf("Decoding Failure - ID: %d Count: %d Ratio:%d \n", f.Id, f.Count, f.Ratio)
			f.trace.failure +=1
			f.trace.blocks +=1
		}		else if (f.Count  == f.Ratio ){    //I means that we lost the FEC packet. We do not need to reconstruct the FEC packet
			f.trace.decoded +=1
			f.trace.blocks +=1
			utils.DebugfFEC("Recovering FEC packet...... \n")

			decodedPacket := &receivedPacket{}
			decodedPacket.remoteAddr = p.remoteAddr
			decodedPacket.rcvTime = p.rcvTime

			decodedPacket.data = make([]byte, len(p.data))

			decodedPacket.header = f.GetDecodeFECHeader(p,true)

			r_packets = append(r_packets, decodedPacket)
			//fmt.Printf("Decoding FEC Succes - ID: %d Count: %d Ratio:%d \n", f.Id, f.Count, f.Ratio)

		}


		f.Id = Id

		traces.StoreFecDecoder ( f.trace.blocks, f.trace.decoded , f.trace.failure , f.trace.redundant )

		utils.DebugfFEC("New BLOCK: %d, ratio: %d", f.Id, p.header.FecRatio)
		f.Ratio = p.header.FecRatio
		f.Count = 0
		f.lastForwarded = 0
		f.storedPackets = nil
		f.unforwardedPackets = nil

		f.randomNumber = uint8(rand.Intn(int(f.Ratio)))
	}



	if (p.header.FecType & (0xC0)) == 0x80 { // Protected packet
		f.Ratio = p.header.FecRatio
		utils.DebugfFEC("Received Protected Packet %d\n", p.header.PacketNumber)

		/*
		//SOME FAKE LOSSES
		if (p.header.FecCount == f.randomNumber){
			utils.DebugfFEC("Packet PN: %d discarted!!", p.header.PacketNumber)
			f.hdr = p.header
			return len(r_packets), r_packets
		}
		*/

		//I store a copy of the packet. Since it is going to be send to the quic flow...
		store := receivedPacket{}
		store.header = p.header
		store.rcvTime = p.rcvTime
		store.remoteAddr = p.remoteAddr
		store.data = make([]byte, len(p.data))

		copy(store.data, p.data)
		f.storedPackets = append(f.storedPackets, &store)

		if (p.header.FecCount == f.lastForwarded) {
			r_packets = append(r_packets, p)
			f.lastForwarded++
			f.lastPacketNumberForwarded = p.header.PacketNumber
			utils.DebugfFEC("FEC1 - Forwarding packet: %d\n", p.header.PacketNumber)
			packets := f.PacketsToForward()
			r_packets = append(r_packets, packets...)

		}else{
			f.unforwardedPackets = append(f.unforwardedPackets,p)
		}

		f.Count++
	}

	if(p.header.FecType & (0xC0)) == 0xC0{  //FEC PACKET
		f.Ratio = p.header.FecRatio
		utils.DebugfFEC("Received FEC packet from %d \n", f.Id)

		if f.Count < f.Ratio - 1{
			utils.DebugfFEC("Decoding Failure - Count: %d, Ratio: %d !!!!!\n", f.Count, f.Ratio)
			f.trace.decoded +=1
			f.trace.blocks +=1
			traces.StoreFecDecoder ( f.trace.blocks, f.trace.decoded , f.trace.failure , f.trace.redundant )
			r_packets = append(r_packets, f.unforwardedPackets...)
			r_packets = append(r_packets, p)
			f.unforwardedPackets = nil
			f.storedPackets = nil
			return len(r_packets), r_packets
		}

		if f.Count == f.Ratio{
			utils.DebugfFEC("Useless FEC Packet - Count: %d, Ratio: %d !!!!!\n", f.Ratio, f.Count)
			r_packets = append(r_packets, f.unforwardedPackets...)
			r_packets = append(r_packets, p)
			f.unforwardedPackets = nil
			f.storedPackets = nil
			f.Count += 1
			return len(r_packets), r_packets
		}

		//f.Count += 1
		packets := f.DecodeFecBlock(p)
		r_packets = append(r_packets, packets...)
		//r_packets = append(r_packets,p)

	}

	utils.DebugfFEC("Return!! %d\n", len(r_packets))
	return len(r_packets), r_packets
}


func (f *FecDecoder) GetFecId(id uint8) (uint64) {

	aux := f.Id

	if (id == uint8(aux)){
		return aux
	}

	if (id < uint8(aux)){
		if (aux > 250){ //In that case we assume that the fecId exceed the uint8
			for id != uint8(aux){
				aux++
			}
		} else{
			return uint64(id)
		}
	}

	if (id > uint8(aux)) {
		for id != uint8(aux){
			aux++
		}
	}

	return aux
}

func (f *FecDecoder) PacketsToForward( ) ([]*receivedPacket) {

	var r_packets []*receivedPacket

	exit := true

	for exit {
		exit = false
		for i := 0; i < len(f.unforwardedPackets); i++ {
			if (f.unforwardedPackets[i].header.FecCount == f.lastForwarded) {
				r_packets = append(r_packets, f.unforwardedPackets[i])
				utils.DebugfFEC("FEC2 - Forwarding packet: %d\n", f.unforwardedPackets[i].header.PacketNumber)
				f.unforwardedPackets = append(f.unforwardedPackets[:i], f.unforwardedPackets[i+1:]...)
				f.lastForwarded++
				exit = true
				break
			}
		}

	}
	return r_packets
}


func (f *FecDecoder) DecodeFecBlock(p *receivedPacket) ([]*receivedPacket) {

	var r_packets []*receivedPacket

	f.MaxLength = protocol.ByteCount(len(p.data))
	utils.DebugfFEC("Decoding...... \n")

	decodedPacket := &receivedPacket{}
	decodedPacket.remoteAddr = p.remoteAddr

	decodedPacket.header = f.hdr

	decodedPacket.rcvTime = p.rcvTime
	decodedPacket.data = make([]byte, len(p.data))
	copy(decodedPacket.data,p.data)


	for i := 0; i < len(f.storedPackets); i++ {
		if (protocol.ByteCount(len(f.storedPackets[i].data)) > f.MaxLength || protocol.ByteCount(len(f.storedPackets[i].data)) == 0){
			utils.DebugfFEC("FEC ERROR MaxLen: %d, Packet Len: %d\n", f.MaxLength, protocol.ByteCount(len(f.storedPackets[i].data)))
			return nil
		}

		for j := 0; j < len(f.storedPackets[i].data); j++ {
			decodedPacket.data[j] = f.storedPackets[i].data[j] ^ decodedPacket.data[j]
		}
	}

	f.unforwardedPackets = append(f.unforwardedPackets, p)
	decodedPacket.header = f.GetDecodeHeader(p, false)
	f.unforwardedPackets = append(f.unforwardedPackets, decodedPacket)

	utils.DebugfFEC("Decoded!! %d\n", decodedPacket.header.PacketNumber)

	//fmt.Printf("Decoded!! %d, Ratio: %d,  Count: %d, Len: %d\n", decodedPacket.header.PacketNumber, decodedPacket.header.FecRatio, decodedPacket.header.FecCount, len(decodedPacket.data))
	//for i:= 0 ; i < len(decodedPacket.header.Raw); i++{
	//	fmt.Printf("%d ",decodedPacket.header.Raw[i])
	//}
	//for i:= 0 ; i < len(p.data); i++{
	//	fmt.Printf("%d ",decodedPacket.data[i])
	//}
	//fmt.Printf("\n")
	//fmt.Printf("\n")

	//fmt.Printf("Decoding Success - ID: %d Count: %d Ratio:%d \n", f.Id, f.Count, f.Ratio)
	packets := f.PacketsToForward()
	r_packets = append(r_packets,packets...)

	f.storedPackets = nil
	//fmt.Printf("Packets Unforwarded: %d\n", len(f.unforwardedPackets))

	return r_packets
}


func (f *FecDecoder) GetDecodeHeader(p *receivedPacket, fec bool)*wire.Header{

	hdr := &wire.Header{}

	// I copy every value since I hace a pointer and not the struct.... Should be better ways to do it
	hdr.ConnectionID = p.header.ConnectionID
	hdr.OmitConnectionID = p.header.OmitConnectionID
	hdr.PacketNumberLen = p.header.PacketNumberLen
	hdr.Version = p.header.Version
	hdr.SupportedVersions = p.header.SupportedVersions
	hdr.IsVersionNegotiation = p.header.IsVersionNegotiation
	hdr.VersionFlag = p.header.VersionFlag
	hdr.ResetFlag = p.header.ResetFlag
	hdr.DiversificationNonce = p.header.DiversificationNonce

	hdr.Type = p.header.Type
	hdr.KeyPhase = p.header.KeyPhase


	//Infer Packet number of lost Packet
	hdr.PacketNumber = f.InferPacketNumber()

	// FEC OPTION WILL NOT LONGER USE but I need them in order to create the raw header, which is used in the decription phase
	var offset uint8
	if(f.lastForwarded == 0){
		offset = 0
	}else{
		offset = uint8(hdr.PacketNumber - f.lastPacketNumberForwarded)
	}


	if (fec){
		hdr.FecType = 0xC0
		hdr.FecId = uint8(f.Id)
		hdr.FecCount = f.Ratio
		hdr.FecRatio = f.Ratio
	}else{
		hdr.FecType = 0x80 | offset
		hdr.FecId = uint8(f.Id)
		hdr.FecCount = f.lastForwarded
		hdr.FecRatio = f.Ratio
	}


	_ = f.writePublicHeader(hdr)

	return hdr
}


func (f *FecDecoder) GetDecodeFECHeader(p *receivedPacket, fec bool)*wire.Header{

	hdr := &wire.Header{}

	// I copy every value since I hace a pointer and not the struct.... Should be better ways to do it
	hdr.ConnectionID = p.header.ConnectionID
	hdr.OmitConnectionID = p.header.OmitConnectionID
	hdr.PacketNumberLen = p.header.PacketNumberLen
	hdr.Version = p.header.Version
	hdr.SupportedVersions = p.header.SupportedVersions
	hdr.IsVersionNegotiation = p.header.IsVersionNegotiation
	hdr.VersionFlag = p.header.VersionFlag
	hdr.ResetFlag = p.header.ResetFlag
	hdr.DiversificationNonce = p.header.DiversificationNonce

	hdr.Type = p.header.Type
	hdr.KeyPhase = p.header.KeyPhase


	//Infer Packet number of lost Packet
	hdr.PacketNumber = p.header.PacketNumber - 1

	// FEC OPTION WILL NOT LONGER USE but I need them in order to create the raw header, which is used in the decription phase
	var offset uint8
	offset = 0



	if (fec){
		hdr.FecType = 0xC0
		hdr.FecId = uint8(f.Id)
		hdr.FecCount = f.Ratio
		hdr.FecRatio = f.Ratio
	}else{
		hdr.FecType = 0x80 | offset
		hdr.FecId = uint8(f.Id)
		hdr.FecCount = f.lastForwarded
		hdr.FecRatio = f.Ratio
	}


	_ = f.writePublicHeader(hdr)

	return hdr
}

func (f *FecDecoder) InferPacketNumber( ) (protocol.PacketNumber) {

	inferedPN := f.unforwardedPackets[0].header.PacketNumber
	offset := f.unforwardedPackets[0].header.FecType & (0x3F)

	for i := 1; i < len(f.unforwardedPackets); i++ {
		if((f.unforwardedPackets[i].header.FecType & 0x80) == 0x80) {
			aux := f.unforwardedPackets[i].header.PacketNumber

			if (aux < inferedPN) {
				inferedPN = aux
				offset = f.unforwardedPackets[i].header.FecType & (0x3F) // I get the last 6 bits 0x30 = 0011 1111
			}
		}
	}

	utils.DebugfFEC("Packet Number Inferred %d: %d \n", inferedPN, offset)

	//The packet
	inferedPN = inferedPN - protocol.PacketNumber(offset)

	return inferedPN
}


// writePublicHeader writes a Public Header.
func (f *FecDecoder) writePublicHeader(h *wire.Header) int {

	raw := *getPacketBuffer()
	b := bytes.NewBuffer(raw[:0])

	if h.VersionFlag && h.ResetFlag {
		return 0
		}

	publicFlagByte := uint8(0x00)
	if h.VersionFlag {
		publicFlagByte |= 0x01
	}
	if h.ResetFlag {
		publicFlagByte |= 0x02
	}
	if !h.OmitConnectionID {
		publicFlagByte |= 0x08
	}
	if len(h.DiversificationNonce) > 0 {
		if len(h.DiversificationNonce) != 32 {
			return 0
			}
		publicFlagByte |= 0x04
	}
	// only set PacketNumberLen bits if a packet number will be written

	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		publicFlagByte |= 0x00
	case protocol.PacketNumberLen2:
		publicFlagByte |= 0x10
	case protocol.PacketNumberLen4:
		publicFlagByte |= 0x20
	case protocol.PacketNumberLen6:
		publicFlagByte |= 0x30
	}

	b.WriteByte(publicFlagByte)

	if !h.OmitConnectionID {
		utils.BigEndian.WriteUint64(b, uint64(h.ConnectionID))
	}
	if h.VersionFlag {
		utils.BigEndian.WriteUint32(b, uint32(h.Version))
	}
	if len(h.DiversificationNonce) > 0 {
		b.Write(h.DiversificationNonce)
	}

	switch h.PacketNumberLen {
	case protocol.PacketNumberLen1:
		b.WriteByte(uint8(h.PacketNumber))
	case protocol.PacketNumberLen2:
		utils.BigEndian.WriteUint16(b, uint16(h.PacketNumber))
	case protocol.PacketNumberLen4:
		utils.BigEndian.WriteUint32(b, uint32(h.PacketNumber))
	case protocol.PacketNumberLen6:
		utils.BigEndian.WriteUint48(b, uint64(h.PacketNumber)&(1<<48-1))
	default:
		return 0
	}

	b.WriteByte(h.FecType)
	b.WriteByte(h.FecId)
	b.WriteByte(h.FecRatio)
	b.WriteByte(h.FecCount)

	raw = raw[0:b.Len()]
	h.Raw = raw

	return 0
}