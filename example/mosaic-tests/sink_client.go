package main

import (
	"crypto/tls"
	"fmt"
	"time"
	"flag"
	//"math/rand"
	quic "github.com/lucas-clemente/quic-go"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/traces"
	"log"
)
//  SINK_CLIENT.GO
//
//	A client that starts a session with a server, then sinks all the information
//
// Pablo Garrido Ortiz - Unican
//
////////////////////////////////////////////////////////////////////////////////////////

func main() {

	ip := flag.String("ip", "localhost:4242", "IP:Port Addres")
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	v := flag.Bool("v", false, "FEC Debug Information")

	packet_size := 1452//Maximum packet size
	buf := make([]byte, packet_size)
	flag.Parse()

	//traces.SetFecDecoderTraceLevel()

	start := time.Now()
	bytesReceived := 0
	fmt.Printf("Start Connection with, %s \n", *ip)

	if(*v) {
		utils.SetLogLevel(utils.LogLevelDebugFEC)
	}

	//Generate QUIC Config
		decoder := &quic.FecDecoder{Ratio: 0,
		Id: 0,
		Count: 0,
		MaxLength: 0}

	config := &quic.Config{
		Encoder: nil,
		Decoder: decoder}

	if (*tcp){   // IF TCP -> Start a connection with TLS/TCP Socket
		start = time.Now()
		conn, err := tls.Dial("tcp", *ip, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Printf("Client listening... \n")

		end := time.Now()
		for{
			end = time.Now()
			conn.SetReadDeadline(time.Now().Add(20*time.Second))
			n, err := conn.Read(buf)
			if (err != nil){
				t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
				thput := float64(bytesReceived*8)/t
				fmt.Printf("Client - Received: %d  bytes, Thput: %f Mbps, %f\n", bytesReceived, thput, t)
				fmt.Printf("Start: %s, End: %s\n", start.String(), end.String())
				break
			}
			bytesReceived = bytesReceived  + n
		}

		//Send a packet to end the communication to the
		fmt.Fprintf(conn, "Se han recibido %d\n", bytesReceived)
		conn.Close()
	}else{
		start = time.Now()
		session, err := quic.DialAddr(*ip, &tls.Config{InsecureSkipVerify: true}, config)
		if err != nil {
			panic(err)
			return
		}
		fmt.Printf("Connection QUIC established \n")

		fmt.Print("Opening New Stream\n")
		stream, err := session.AcceptStream()
		if err != nil {
			return
		}
		fmt.Printf("Stream: %d Accepted \n", uint64(stream.StreamID()))


		//init_message := make([]byte, 1000)  // Generate a message of PACKET_SIZE full of random information
		//rand.Read(init_message)
		//_,_ = stream.Write([]byte(init_message))

		//time.Sleep(100 * time.Second)
		fmt.Printf("Client listening... \n")
		end := time.Now()
		for{
			end = time.Now()
			stream.SetReadDeadline(time.Now().Add(2000*time.Second))
			n, err := stream.Read(buf)
			if (err != nil){
				t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
				thput := float64(bytesReceived*8)/t
				fmt.Printf("Client - Received: %d  bytes, Thput: %f Mbps, %f\n", bytesReceived, thput, t)
				//fmt.Printf("Start: %s, End: %s\n", start.String(), end.String())
				break
			}
			bytesReceived = bytesReceived  + n
		}


		//Send a packet to end the communication to the
		fmt.Fprintf(stream, "Se han recibido %d\n", bytesReceived)

		stream.Close()
		session.Close(nil)

		traces.PrintFecDecoder()
	}
	return
}

