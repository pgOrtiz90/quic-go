package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

func main() {
	logName := "server_bulk"
	prefix := "Server "

	//------------------ Server flags
	timeOut := flag.String("timeout", "2m", "Server waiting for client timeout")
	confJson := flag.String("json", "server.json", "Path to json with rQUIC Conf.")
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
	mb := flag.Int("mb", 1, "File size in MiB")
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

	// Set current working directory
	if *wdir != "" {
		if err := os.Chdir(*wdir); err != nil {
			fmt.Println("Failed to change working directory: " + err.Error())
			dir, err := os.Getwd()
			fmt.Println("Current working directory: " + dir)
			if err != nil {
				fmt.Println("Failed to get current working directory: " + err.Error()) // Definitely not your day...
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
		rLogger.Logf(err.Error()) // Try to log the error if the logger could be initiated
		fmt.Println(err)
	} else {
		rLogger.Logf("Initiating")
	}

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
		} else {
			fmt.Println(ee)
		}
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

	//------------------ Server configuration

	// Create the message to send
	maxSendBytes, bytesSent := (*mb) * 1024 * 1024, 0
	message := make([]byte, maxSendBytes) // Generate a message of PACKET_SIZE full of random information
	if n, err := rand.Read(message); err != nil || n < maxSendBytes {
		panic(fmt.Sprintf("Failed to create test message: wrote %d/%d Bytes; %v\n", n, maxSendBytes, err))
	}

	// Create a buffer for receiving client's report
	maxPacketSize := protocol.MaxPacketSizeIPv4
	buf := make([]byte, maxPacketSize)
	var n int

	//------------------ Connection

	// Listen on the given network address for QUIC connection
	tlsconf := generateTLSConfig()
	listener, err := quic.ListenAddr(*ip, tlsconf, config)
	defer listener.Close()
	if err != nil {
		printError("Error listening tls on " + *ip + ": " + err.Error())
		return
	}

	// Listen on the given network address for a TCP+TLS connection
	tcpAddr, err := net.ResolveTCPAddr("tcp", *ip)
	if err != nil {
		printError("Error resolving TCP address " + *ip + ": " + err.Error())
		return
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		printError("Error listening TCP address " + *ip + ": " + err.Error())
		return
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, tlsconf)
	defer tlsConn.Close()

	printInfo("Waiting: " + *ip)

	//err1 := make(chan error)
	//err2 := make(chan error)
	connChann := make(chan net.Conn)
	sessChann := make(chan quic.Session)

	var start, end time.Time

	go func() {
		sess, _ := listener.Accept(context.Background())
		start = time.Now()
		sessChann <- sess
	}()

	go func() {
		conn, _ := tlsConn.Accept()
		start = time.Now()
		connChann <- conn
	}()

	dur, _ := time.ParseDuration(*timeOut)
	timeout := time.NewTimer(dur)

	select {
	case <- timeout.C:
		printError("No connection after " + *timeOut)

	case sess := <-sessChann: // QUIC session
		printInfo("Established QUIC connection")
		prefix += "QUIC "
		outputData = rQC.Overview()

		//stream, err := sess.AcceptStream()
		stream, err := sess.OpenStreamSync(context.Background()) // Apparently, if no data is transmitted it does not open any stream
		if err != nil {
			printError("Stream Open Error: " + err.Error())
			return
		}
		printInfo("Sending...")

		n, err = stream.Write([]byte(message))
		end = time.Now()
		bytesSent += n
		if err != nil {
			printError("Stream Write Error: " + err.Error())
		}

		n, err = stream.Read(buf)
		if err != nil {
			printError("Stream Read Error: " + err.Error())
		}

		// Close stream and connection
		var errMsg string
		if err = stream.Close(); err != nil {
			errMsg += "; StreamErr: " + err.Error()
		}
		if err = sess.CloseWithError(0, ""); err != nil {
			errMsg += "; SessionErr: " + err.Error()
		}
		if errMsg != "" {
			printError("Connection closed with errors" + errMsg)
		} else {
			printInfo("Connection closed")
		}

	case conn := <-connChann: //TCP Connection
		printInfo("Established TCP connection")
		prefix += "TCP "
		outputData = "TCP" + rquic.ConfOverviewEmpty
		printInfo("Sending...")

		// TCP
		n, err = conn.Write([]byte(message))
		end = time.Now()
		bytesSent += n
		if err != nil {
			printError("Write Error: " + err.Error())
		}

		n, err = conn.Read(buf)
		if err != nil {
			printError("Read Error: " + err.Error())
		}

		// Close connection
		if err = conn.Close(); err != nil {
			printError("Connection closed with error: " + err.Error())
		} else {
			printInfo("Connection closed")
		}

	}

	printInfo("Report Client - " + string(buf[:n]))

	//------------------ Process output

	t := float64(end.Sub(start)) / 1000 // us from conn. establishment to end of data Tx
	thput := float64(bytesSent*8) / t
	printInfo("Report Server - Transmitted(B):%d/%d Time(us):%f Throughput(Mbps):%f", bytesSent, maxSendBytes, t, thput)
	rLogger.Stop()

	// Write Xput and Completion time to csv
	//if simOut, err := os.OpenFile(*logFileName+"_simOut.csv", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666); err != nil {
	//	printError("Failed to open simOut: " + err.Error())
	//} else {
	//	if simOutStat, err := simOut.Stat(); err == nil && simOutStat != nil {
	//		if simOutStat.Size() == 0 {
	//			// write header
	//			if _, err := simOut.WriteString(rquic.ConfOverviewHeader + ",Throughput(Mbps),Duration(us),Sent(B),Message(B)," + rLogger.CountersReportHeader + "\n"); err != nil {
	//				printError("Error when writing simOut header: " + err.Error())
	//			}
	//		}
	//	}
		outputData += fmt.Sprintf(",%f,%f,%d,%d,", thput, t, bytesSent, maxSendBytes) + rLogger.CountersReport()
	//	if _, err := simOut.WriteString(outputData + "\n"); err != nil {
	//		printError("Error when writing \"" + outputData + "\" to simOut: " + err.Error())
	//	}
	//	if err = simOut.Close(); err != nil {
	//		printError("Error when closing simOut: " + err.Error())
	//	}
	//}
	fmt.Println("rSimRes:Srv:" + outputData)

	//time.Sleep(time.Second)
	return
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privKeyFile := "/home/administrator/key.key"
	ioutil.WriteFile(privKeyFile, keyPEM, 0644)

	pre_key := "/home/administrator/cert.pem"
	ioutil.WriteFile(pre_key, certPEM, 0644)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos: []string{"bulk_server_client_sink"},
	}
}
