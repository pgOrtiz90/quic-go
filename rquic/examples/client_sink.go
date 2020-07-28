package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

//  SINK_CLIENT.GO
//
//	A client that starts a session with a server, then sinks all the information
//
//  Pablo Garrido Ortiz - Univ. of Cantabria & Ikerlan
//  Mihail Zverev       - Univ. of Cantabria & Ikerlan
//

func main() {
	traceFile := "client_sink"

	ip := flag.String("ip", "localhost:4242", "IP:Port Address")
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	rtt := flag.Int("rtt", 25, "RTT avg. (ms)")
	logFileName := flag.String("logFileName", traceFile, "Trace File Name")
	trace := flag.Bool("trace", false, "FEC TRACES")
	debug := flag.Bool("debug", false, "rQUIC Debug Information")
	flag.Parse()

	var prefix, prefixConn string
	// Enable tracing
	if *trace {
		prefix = "Client "
		// Set trace file name
		if *logFileName == traceFile {
			// If trace file name is the default one, add a date-time stamp.
			traceFile += time.Now().Format("_060102-150405")
		} else {
			traceFile = *logFileName
		}
		// Initiate the tracer (logger)
		rLogger.Init(traceFile, *debug)
		if rLogger.IsEnabled() {
			rLogger.Printf("Initiating")
		} else {
			fmt.Println("Tracer could not be initiated")
			return
		}
	}

	var start, end time.Time
	var t, thput float64 // end - start & throughput
	var bytesReceived int
	// timeFormat := "15:04:05.000000" // us
	timeFormat := "15:04:05.000000000" // ns
	var errMsg string
	buf := make([]byte, protocol.MaxPacketSizeIPv4) // > MaxPacketSizeIPv6

	// Client is not going to send anything. Encoder can still be enabled, leaving it with default values
	config := &quic.Config{RQuic: &rquic.Conf{
		EnableEncoder: true,
		EnableDecoder: true,
		CodingConf:    &rquic.CConf{TPeriod: 3 * time.Duration(*rtt) * time.Millisecond},
	}}

	fmt.Printf("Start Connection with, %s \n", *ip)
	if *tcp {
		prefixConn = prefix + "TCP "
		start = time.Now()
		conn, err := tls.Dial("tcp", *ip, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Println(err)
			rLogger.Logf(prefixConn + "Error:" + err.Error())
			return
		}
		fmt.Printf("Client listening... \n")

		for {
			end = time.Now()

			if err = conn.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
				rLogger.Logf(prefixConn + "")
			}

			n, err := conn.Read(buf)
			if err != nil {
				t = float64(end.Sub(start)) / 1000 // us from conn. establishment to the last Rx packet
				thput = float64(bytesReceived*8) / t
				fmt.Printf("Client - Received: %d  bytes, Thput: %f Mbps, %f\n", bytesReceived, thput, t)
				fmt.Printf("Start: %s, End: %s\n", start.Format(timeFormat), end.Format(timeFormat))
				rLogger.Logf(prefixConn+"Stats Received(MB):%d Time(us):%f Throughput(Mbps):%f", bytesReceived, t, thput)
				break
			}
			bytesReceived += n
		}

		fmt.Fprintf(conn, "Se han recibido %d bytes\n", bytesReceived)

		// Close connection
		errMsg = ""
		if err = conn.Close(); err != nil {
			errMsg += " with Error:" + err.Error()
		}
		if rLogger.IsEnabled() {
			rLogger.Printf(prefixConn + "Closed" + errMsg)
			rLogger.Disable()
		}

	} else /* QUIC */ {
		prefixConn = prefix + "QUIC "
		start = time.Now()
		session, err := quic.DialAddr(
			*ip,
			&tls.Config{
				InsecureSkipVerify: true,
				NextProtos: []string{"bulk_server_client_sink"},
			},
			config,
		)
		if err != nil {
			panic(err)
			return
		}
		fmt.Printf("QUIC connection established \n")

		fmt.Print("Opening New Stream\n")
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			return
		}
		fmt.Printf("Stream: %d Accepted \n", uint64(stream.StreamID()))
		fmt.Printf("Client listening... \n")

		for {
			end = time.Now()
			stream.SetReadDeadline(time.Now().Add(2000 * time.Second))
			n, err := stream.Read(buf)
			if err != nil {
				t = float64(end.Sub(start)) / 1000 // us from conn. establishment to the last Rx packet
				thput = float64(bytesReceived*8) / t
				fmt.Printf("Client - Received: %d  bytes, Thput: %f Mbps, %f\n", bytesReceived, thput, t)
				//fmt.Printf("Start: %s, End: %s\n", start.String(), end.String())
				rLogger.Logf(prefixConn+"Stats Received(MB):%d Time(us):%f Throughput(Mbps):%f", bytesReceived, t, thput)
				break
			}
			bytesReceived = bytesReceived + n
		}

		//Send a packet to end the communication to the
		fmt.Fprintf(stream, "Se han recibido %d\n", bytesReceived)

		// Close stream and connection
		errMsg = ""
		if err = stream.Close(); err != nil {
			errMsg += "; StreamErr:" + err.Error()
		}
		if err = session.CloseWithError(0, ""); err != nil {
			errMsg += "; SessionErr:" + err.Error()
		}
		if errMsg != "" {
			errMsg = " with errors" + errMsg
		}
		if rLogger.IsEnabled() {
			rLogger.Printf(prefixConn + "Closed" + errMsg)
			rLogger.Disable()
		}
	}

	return
}
