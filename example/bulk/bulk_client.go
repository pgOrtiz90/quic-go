//  BULK_CLIENT.GO 
//
//	A client that transmits as much information as possible to a sink application
//
// Pablo Garrido Ortiz - Unican
// 
////////////////////////////////////////////////////////////////////////////////////////

package main

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"time"
	"flag"

	quic "github.com/lucas-clemente/quic-go"
)

func main() {

	ip := flag.String("ip", "localhost:4242", "IP:Port Addres")
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	packet_size := flag.Int("l", 1400, "Packet Length Size")
	mb := flag.Int("mb", 1, "File size in Mbytes")
	flag.Parse()
	
	max_send_bytes := (*mb)*1024*1024;
	
	message := make([]byte, *packet_size)  // Generate a message of PACKET_SIZE full of random information
    rand.Read(message)

	start := time.Now()
	bytesSent := 0
	if (*tcp){		
		conn, _ := tls.Dial("tcp", *ip, &tls.Config{InsecureSkipVerify: true})
		fmt.Printf("Client: Sending\n")
		
		for bytesSent < max_send_bytes{
			n, err:= conn.Write([]byte(message))
			if err != nil {
				return 
			}
			bytesSent = bytesSent + n;
		}	
	}else{
		session, err := quic.DialAddr(*ip, &tls.Config{InsecureSkipVerify: true}, nil)
		if err != nil {
			return 
		}
	
		stream, err := session.OpenStream()
		if err != nil {
			return 
		} 
		fmt.Printf("Client: Sending\n")

		for bytesSent < max_send_bytes{
			n, err := stream.Write([]byte(message))
			if err != nil {
				return 
			}
			bytesSent = bytesSent + n;
		}
		
	}
	end := time.Now();
	t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
	thput := float64(bytesSent*8)/t
	fmt.Printf("Client - Sent: %d  bytes, Thput: %f Mbps\n", bytesSent, thput)
	
	return 
}


