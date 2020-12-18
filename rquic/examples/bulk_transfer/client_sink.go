package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

//  SINK_CLIENT.GO
//
//	A client that starts a session with a server, then sinks all the information
//
//  Pablo Garrido Ortiz - Univ. of Cantabria & Ikerlan
//  Mihail Zverev       - Univ. of Cantabria & Ikerlan
//

func main() {
	logName := "client_sink"
	prefix := "Client "

	//------------------ Client flags
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	letSrvInit := flag.Int("letSrvInit", 200, "Milliseconds to give server time to start")
	confJson := flag.String("json", "client.json", "Path to json with rQUIC Conf.")
	//------------------ Common flags
	ip := flag.String("ip", "localhost:4242", "IP:Port Address")
	trace := flag.Bool("trace", false, "Enable rQUIC traces")
	doLog := flag.Bool("log", false, "Enable rQUIC logging")
	debug := flag.Bool("debug", false, "Enable rQUIC debug logging (if true, ignores log)")
	info := flag.Bool("info", false, "Print informative messages")
	verbose := flag.Bool("v", false, "verbose (QUIC detailed logs)")
	wdir := flag.String("wdir", "", "Working directory. All relative paths take it as reference.")
	logFileName := flag.String("outputFile", logName, "Path to trace file")
	writeDefaultTestEnvironment := flag.Bool("writeDef", false, "Writes default rQUIC conf to json.")
	mb := flag.Int("mb", 1, "Expect to receive a file of size in MiB")
	BTOMargin := flag.Int("BTOMargin", rquic.BTOMargin, "")
	BTOOnly := flag.Bool("BTOOnly", false, "")
	PauseEncodingWith := flag.Int("PauseEncodingWith", rquic.PauseEncodingNever, "")
	ResLossFactor := flag.Float64("ResLossFactor", rquic.ResLossFactor, "")
	LimRateToDecBuffer := flag.Bool("LimRateToDecBuffer", false, "")
	flag.Parse()

	//------------------ Digest flags, define tools

	rquic.BTOMargin = *BTOMargin
	rquic.BTOOnly = *BTOOnly
	rquic.PauseEncodingWith = *PauseEncodingWith
	rquic.ResLossFactor = *ResLossFactor
	rquic.LimRateToDecBuffer = *LimRateToDecBuffer

	// QUIC logger
	logger := utils.DefaultLogger
	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	}
	logger.SetLogTimeFormat(rLogger.TimeHuman)

	// Print or log informative messages as specified by flags.
	quiet := !*info
	printInfo := func(format string, a ...interface{}) {
		msg := prefix + fmt.Sprintf(format, a...)
		if rLogger.IsLogging() {
			rLogger.Printf(msg)
		}
		if quiet {
			return
		}
		fmt.Println(msg)
	}

	// Print or log errors as specified by flags. If not logging, errors will be printed to std.Out.
	printError := func(e string) {
		ee := prefix + e
		if rLogger.IsLogging() {
			rLogger.Printf(ee)
			if *info {
				fmt.Println(ee)
			}
			return
		}
		fmt.Println(ee)
	}

	// Set current working directory
	if *wdir != "" {
		if err := os.Chdir(*wdir); err != nil {
			printError("Failed to change working directory: " + err.Error())
			dir, err := os.Getwd()
			printError("Current working directory: " + dir)
			if err != nil {
				printError("Failed to get current working directory: " + err.Error()) // Definitely not your day...
			}
		}
	}

	// Initiate the trace/log writer
	if *logFileName == logName {
		// If trace file name is the default one, add a date-time stamp.
		logName += "_" + time.Now().Format(rLogger.TimeShort)
	} else {
		logName = *logFileName
	}
	if err := rLogger.Init(logName, *trace, *doLog, *debug); err != nil {
	} else {
		rLogger.Logf("Initiating")
	}

	// Read/Generate QUIC Config
	var rQC *rquic.Conf
	var err error
	if *writeDefaultTestEnvironment {
		rQC = rquic.GetConfTx(nil) // rQC points to a Conf with default values
		if err := rQC.WriteJson(*confJson); err != nil {
			printError("Default rQUIC conf could not be written: " + err.Error())
		}
	} else {
		rQC, err = rquic.ReadConfFromJson(*confJson) // rQC points to the expected or to an empty Conf
		if err != nil {
			printError("rQUIC conf loaded with errors: " + err.Error())
		}
	}
	config := &quic.Config{RQuic: rQC}
	rLogger.TakeNote("rQUIC Conf: " + rQC.String()) // rQC is not nil

	// Output string
	var outputData string

	//------------------ Client configuration

	var start, end time.Time
	var bytesReceived int
	buf := make([]byte, protocol.MaxPacketSizeIPv4) // > MaxPacketSizeIPv6
	reply := func() string { return fmt.Sprintf("Received(B):   %d", bytesReceived) }

	// Receiving loop for TCP and QUIC is pretty much the same
	type readFromConn interface {
		SetReadDeadline(t time.Time) error
		Read(p []byte) (n int, err error)
	}
	receiveAsMuchAsPossible := func(conn readFromConn) {
		for {
			end = time.Now()

			if err := conn.SetReadDeadline(end.Add(20 * time.Second)); err != nil {
				printError("Could not set connection read deadline: " + err.Error())
			}

			if n, err := conn.Read(buf); err != nil {
				break
			} else {
				bytesReceived += n
			}
		}
		printInfo("Read deadline reached, finishing")
	}

	//------------------ Connection

	time.Sleep(time.Duration(*letSrvInit) * time.Millisecond) // Let Server Init itself
	printInfo("Start Connection with " + *ip)

	if *tcp {
		prefix += "TCP "
		outputData = "TCP" + rquic.ConfOverviewEmpty
		start = time.Now()
		conn, err := tls.Dial("tcp", *ip, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			printError("Error establishing TCP+TLS connection: " + err.Error())
			return
		}
		printInfo("Listening...")

		receiveAsMuchAsPossible(conn)

		if _, err := fmt.Fprintf(conn, reply()); err != nil {
			printError("Connection write error: " + err.Error())
		}

		// Close connection
		if err = conn.Close(); err != nil {
			printError("Connection closed with error: " + err.Error())
		} else {
			printInfo("Connection closed")
		}

	} else /* QUIC */ {
		prefix += "QUIC "
		outputData = rQC.Overview()
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
		printInfo("Connection established")

		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			return
		}
		printInfo("Stream: %d Accepted. Listening...", uint64(stream.StreamID()))

		receiveAsMuchAsPossible(stream)

		// Send a packet to end the communication
		if _, err := stream.Write([]byte(reply())); err != nil {
			printError("Stream write error: " + err.Error())
		}
		time.Sleep(time.Duration(*letSrvInit) * time.Millisecond) // Give server a breath, and then close the connection

		// Close stream and connection
		var errMsg string
		if err = stream.Close(); err != nil {
			errMsg += "; StreamErr:" + err.Error()
		}
		if err = session.CloseWithError(0, ""); err != nil {
			errMsg += "; SessionErr:" + err.Error()
		}
		if errMsg != "" {
			printError("Connection closed with errors" + errMsg)
		} else {
			printInfo("Connection closed")
		}
	}

	//------------------ Process output

	t := float64(end.Sub(start)) / 1000 // us from conn. establishment to the last Rx packet
	thput := float64(bytesReceived*8) / t
	printInfo(fmt.Sprintf("Report Client - Received(B):%d/%d Time(us):%f Throughput(Mbps):%f", bytesReceived, *mb*1024*1024, t, thput))
	rLogger.Stop()

	// Write Xput and Completion time to csv
	//if simOut, err := os.OpenFile(*logFileName+"_simOut.csv", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
	//	printError("Failed to open simOut: " + err.Error())
	//} else {
	//	if simOutStat, err := simOut.Stat(); err == nil && simOutStat != nil {
	//		if simOutStat.Size() == 0 {
	//			// write header
	//			if _, err := simOut.WriteString(rquic.ConfOverviewHeader + ",Throughput(Mbps),Duration(us),Received(B)," + rLogger.CountersReportHeader + "\n"); err != nil {
	//				printError("Error when writing simOut header: " + err.Error())
	//			}
	//		}
	//	}
		outputData += fmt.Sprintf(",%f,%f,%d,", thput, t, bytesReceived) + rLogger.CountersReport()
	//	if _, err := simOut.WriteString(outputData + "\n"); err != nil {
	//		printError("Error when writing \"" + outputData + "\" to simOut: " + err.Error())
	//	}
	//	if err = simOut.Close(); err != nil {
	//		printError("Error when closing simOut: " + err.Error())
	//	}
	//}
	fmt.Println("rSimRes:Cli:" + outputData)

	return
}
