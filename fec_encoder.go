package quic

import (
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/wire"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"time"
	"github.com/lucas-clemente/quic-go/traces"
)

type FecEncoder struct{
	Id				uint64
	Ratio			uint8
	Count 		uint8
	FECData   []byte
	MaxLength protocol.ByteCount
	lastPacketNumber protocol.PacketNumber

	dynamicRatio *dynamicFecRatio
	Dynamic bool
	Timer time.Duration
	N		uint
	Delta float64
	Target float64

	ratio_aux uint8
}


type dynamicFecRatio struct{
	Ratio float64
	timer time.Duration
	N		uint
	delta float64

	rtx uint32
	tx uint32
	residual float64
	target float64
	n uint

	encoder *FecEncoder
}




//Store transmitted packets in order to create FEC packets
func (f *FecEncoder) ParsePacket(raw []byte, header *wire.Header) int{
	utils.DebugfFEC("Parse Packet %d\n", len(f.FECData))
	if f.Ratio == 0 {
		return 0
	}

	if (f.Dynamic == true) {

		if (f.Id == 0 && f.Count == 0) {
			f.dynamicRatio = &dynamicFecRatio{Ratio: float64(f.Ratio),
				timer: f.Timer,
				N: f.N,
				delta: f.Delta,
				rtx: 0,
				tx: 0,
				residual: 0,
				target: f.Target,
				n: 0,
				encoder: f}
			traces.FecEncoderTraceInit(f.Ratio, 0.33, 0.01, f.N, f.Timer)
			traces.PrintFecEncoder(f.Ratio)
			f.ratio_aux = f.Ratio
			go f.dynamicRatio.StartTimer()
		}
	}
	f.Count = f.Count + 1

	if(f.dynamicRatio != nil) {
		f.dynamicRatio.AddTransmissionCount()
	}

	if f.Count > f.Ratio{ //Error
		return 1
	}

	length := protocol.ByteCount(len(raw))
	if length > f.MaxLength{
		//We need to increase FECData
		f.FECData = append(f.FECData, make([]byte, (length - f.MaxLength))...)
		f.MaxLength =  length
	}

	for i := protocol.ByteCount(0); i < length; i++ {
		f.FECData[i] = f.FECData[i] ^ raw[i]
	}

	f.lastPacketNumber = header.PacketNumber

	return 0
}

func (f *FecEncoder) TransmitFecPacket() bool{

	if f.Ratio == 0{  //If ratio is zero -> Never transmit FEC Packets
		return false
	}
	return f.Count >= f.Ratio
}

func (f *FecEncoder) ComposeFecPacket () (*wire.FecFrame, error){

	if (f.Count < f.Ratio){
		utils.DebugfFEC("Lower FEC BLOCK - Ratio: %d, Count: %d \n", f.Ratio, f.Count)
	}

	frame := &wire.FecFrame{}
	frame.Data = make([]byte, f.MaxLength)
	copy(frame.Data, f.FECData)

	//Update values
	f.FECData = nil
	f.Count = 0
	f.Ratio = f.ratio_aux
	f.MaxLength = 0
	f.Id += 1

	return frame, nil
}


func (f *FecEncoder) GetFecType(number protocol.PacketNumber)uint8{

	aux := uint8(number - f.lastPacketNumber)

	if (f.Count == 0){  // First Packet in the FEC blcok
		aux = (0x80)^(0x00)
		return aux
	}

 if aux > 64{
 		utils.DebugfFEC("FEC- Last protected packet to old...\n")
		return 0
 }

	aux = (0x80)^(aux)
	return aux

}


func (f *FecEncoder) AddRetransmissionCount(){
	if(f.dynamicRatio != nil) {
		f.dynamicRatio.AddRetransmissionCount()
	}
}

func (f *FecEncoder) SetLastPacketNumber(number protocol.PacketNumber){
	f.lastPacketNumber = number
}


func (f *FecEncoder) ChangeFecRatio(ratio uint8){
	f.ratio_aux = ratio
	f.Ratio = ratio
	if(f.dynamicRatio != nil) {
		f.dynamicRatio.Ratio = float64(ratio)
	}
	traces.PrintFecEncoder(f.Ratio)
}

func (d *dynamicFecRatio) StartTimer(){
	d.n = 0
	d.residual = 0
	d.rtx = 0
	d.tx  = 0
	for {
		timer := time.NewTimer(d.timer)
		//go func() {
			<-timer.C

			d.residual += float64(d.rtx)/float64(d.tx - d.rtx)
			d.n++
			d.rtx = 0
			d.tx  = 0

			if(d.n >= d.N){
				d.UpdateRatio()
				d.residual = 0
				d.n = 0
			}
		//}()
	}
}


func (d *dynamicFecRatio) AddRetransmissionCount(){
	d.rtx++
}

func (d *dynamicFecRatio) AddTransmissionCount(){
	d.tx++
}


func (d *dynamicFecRatio) UpdateRatio(){

	residual := d.residual/float64(d.N)

	if(residual > d.target) {
		d.Ratio = d.Ratio * (1 - d.delta)
	}else{
		d.Ratio = d.Ratio * (1 + d.delta)
	}

	if (d.Ratio > 255){
		d.Ratio = 255
	}

	if (d.Ratio < 2){
		d.Ratio = 2
	}

	d.encoder.ratio_aux = uint8(int(d.Ratio))
	traces.PrintFecEncoder(d.encoder.Ratio)
	//fmt.Printf("Update Ratio Old: %d, New: %f, residual: %f, Target: %f N: %d\n", d.encoder.Ratio, d.Ratio, residual, d.target,d.N)
}