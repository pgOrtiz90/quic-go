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
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)

func main() {
	traceFile := "bulk_server"

	ip := flag.String("ip", "localhost:4242", "IP:Port Address")
	mb := flag.Int("mb", 1, "File size in Mbytes")
	fecRatio := flag.Int("ratio", 4, "Fec Ratio")
	dynamic := flag.Bool("dynamic", true, "Dynamic FEC Ratio (static if false)")
	rtt := flag.Int("rtt", 25, "RTT avg. (ms)")
	NumPeriods := flag.Int("NumPeriods", 3, "T=N*RTT")
	deltaRatio := flag.Float64("deltaRatio", 0.33, "T=N*RTT")
	gammaTarget := flag.Float64("gammaTarget", 0.01, "Target of Dynamic FEC algorithm")
	//id := flag.Uint("ID", 0, "RUN IDENTIFIER")
	//cwnd := flag.Bool("cwnd", false, "CWND PRINT")
	logFileName := flag.String("logFileName", traceFile, "Trace File Name")
	trace := flag.Bool("trace", false, "FEC Traces")
	debug := flag.Bool("debug", false, "rQUIC Debug Information")
	timeOut := flag.String("timeOut", "2m", "Server waiting timeout")
	flag.Parse()

	fmt.Printf("Init Server \n")

	// Enable tracing
	var prefix, prefixConn string
	if *trace {
		prefix = "Server "
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

	// Generate QUIC Config
	config := &quic.Config{RQuic: &rquic.Conf{EnableEncoder: true, EnableDecoder: true, CodingConf: &rquic.CConf{
		Scheme:   rquic.SchemeXor,
		RatioVal: float64(*fecRatio),
		//Dynamic:     int(*dynamic) * 2 - 1, // no bool to int convertions in Go
		TPeriod:     3 * time.Duration(*rtt) * time.Millisecond,
		NumPeriods:  *NumPeriods,
		GammaTarget: *gammaTarget,
		DeltaRatio:  *deltaRatio,
	}}}
	if *dynamic {
		config.RQuic.CodingConf.Dynamic = 1
	} else {
		config.RQuic.CodingConf.Dynamic = -1
	}

	max_send_bytes := (*mb) * 1024 * 1024
	bytesSent := 0

	message := make([]byte, max_send_bytes) // Generate a message of PACKET_SIZE full of random information
	rand.Read(message)

	// Listen on the given network address for QUIC connection
	tlsconf := generateTLSConfig()
	listener, err := quic.ListenAddr(*ip, tlsconf, config)
	defer listener.Close()
	if err != nil {
		fmt.Println(err)
		return
	}

	// Listen on the given network address for a TCP+TLS connection
	tcpAddr, err := net.ResolveTCPAddr("tcp", *ip)
	if err != nil {
		fmt.Println(err)
		return
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, tlsconf)
	defer tlsConn.Close()

	fmt.Printf("Server waiting: %s \n", *ip)

	//err1 := make(chan error)
	//err2 := make(chan error)
	conn_chann := make(chan net.Conn)
	sess_chann := make(chan quic.Session)

	var start, end time.Time
	var errMsg string

	go func() {
		sess, _ := listener.Accept(context.Background())
		start = time.Now()
		sess_chann <- sess
	}()

	go func() {
		conn, _ := tlsConn.Accept()
		start = time.Now()
		conn_chann <- conn
	}()

	dur, _ := time.ParseDuration(*timeOut)
	timeout := time.NewTimer(dur)

	select {
	case <- timeout.C:
		fmt.Printf("No connection after %s.\n", *timeOut)

	case sess := <-sess_chann: // QUIC session

		fmt.Println("Established QUIC connection")
		prefixConn = prefix + "QUIC "
		rLogger.Logf(prefixConn + "Connection Established")

		//stream, err := sess.AcceptStream()
		stream, err := sess.OpenStreamSync(context.Background()) // Apparently, if no data is transmitted it does not open any stream
		if err != nil {
			rLogger.Logf(prefixConn + "Stream Open Error:" + err.Error())
			panic(err)
		}

		fmt.Printf("Server: Sending\n")
		bytesSent = 0

		n, err := stream.Write([]byte(message))
		bytesSent += n
		end = time.Now()
		if err != nil {
			rLogger.Logf(prefixConn + "Stream Write Error:" + err.Error())
			fmt.Printf("Error \n")
			fmt.Print(err)
		} else {
			fmt.Printf("Without error\n")
		}

		packet_size := 1452 // Maximum packet size
		//packet_size := protocol.MaxPacketSizeIPv4 // > MaxPacketSizeIPv6
		buf := make([]byte, packet_size)
		n, err = stream.Read(buf)
		if err != nil {
			rLogger.Logf(prefixConn + "Stream Read Error:" + err.Error())
		}
		fmt.Printf("-> %s", string(buf[:n]))

		// Close stream and connection
		errMsg = ""
		if err = stream.Close(); err != nil {
			errMsg += "; StreamErr:" + err.Error()
		}
		if err = sess.CloseWithError(0, ""); err != nil {
			errMsg += "; SessionErr:" + err.Error()
		}
		if errMsg != "" {
			errMsg = " with errors" + errMsg
		}
		rLogger.Logf(prefixConn + "Closed" + errMsg)

	case conn := <-conn_chann: //TCP Connection

		bytesSent = 0

		fmt.Println("Established TCP connection")
		prefixConn = prefix + "TCP "
		rLogger.Logf(prefixConn + "Connection Established")

		fmt.Printf("Sever: Sending.... \n")

		n, err := conn.Write([]byte(message))
		bytesSent += n
		end = time.Now()
		if err != nil {
			rLogger.Logf(prefixConn + "Write Error:" + err.Error())
			fmt.Printf("Error \n")
			fmt.Print(err)
		} else {
			fmt.Printf("Without error\n")
		}

		packet_size := 1452 // Maximum packet size
		buf := make([]byte, packet_size)
		n, err = conn.Read(buf)
		if err != nil {
			rLogger.Logf(prefixConn + "Read Error:" + err.Error())
		}
		fmt.Printf("-> %s", string(buf[:n]))

		// Close connection
		errMsg = ""
		if err = conn.Close(); err != nil {
			errMsg += " with Error:" + err.Error()
		}
		rLogger.Logf(prefixConn + "Closed" + errMsg)

	}

	t := float64(end.Sub(start)) / 1000 // us from conn. establishment to end of data Tx
	thput := float64(bytesSent*8) / t
	fmt.Printf("Server - Sent: %d  bytes, Thput: %f Mbps, %f us\n", bytesSent, thput, t)
	//fmt.Printf("Start: %s, End: %s\n", start.String(), end.String())
	if rLogger.IsEnabled() {
		rLogger.Printf(prefix+"Connection Closed Stats Transmitted(MB):%d Time(us):%f Throughput(Mbps):%f",
			bytesSent, t, thput,
		)
		rLogger.Disable()
	}

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
