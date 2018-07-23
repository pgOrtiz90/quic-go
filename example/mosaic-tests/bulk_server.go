package main

import (
"crypto/rand"
"crypto/rsa"
"crypto/tls"
"crypto/x509"
"encoding/pem"
"fmt"
"net"
"io/ioutil"
"time"
"math/big"
"flag"
quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/traces"
)

func main() {

	ip := flag.String("ip", "localhost:4242", "IP:Port Addres")
	mb := flag.Int("mb", 1, "File size in Mbytes")
	v := flag.Bool("v", false, "FEC Debug Information")
	fecRatio := flag.Int("ratio", 4, "Fec Ratio")
	trace := flag.String("trace","bulk_server", "Trace File Name")
	rtt := flag.Int("rtt",20, "RTT avg.")
	N := flag.Uint("N",3, "T=N*RTT")
	delta := flag.Float64("delta",0.33, "T=N*RTT")
	target := flag.Float64("target",0.01, "Target of Dynamic FEC algorithm")
	id := flag.Uint("ID",0, "RUN IDENTIFIER")
	cwnd := flag.Bool("cwnd",false, "CWND PRINT")

	flag.Parse()

	if(*v) {
		utils.SetLogLevel(utils.LogLevelDebugFEC)
		//utils.SetLogLevel(utils.LogLevelDebug)
    }


	traces.SetTraceFileName(*trace)

	if (*cwnd ) {
		traces.SetFecEncoderTraceLevel()
		traces.SetCWNDTraceLevel()
	}

	traces.SetAPPTraceLevel()



	fmt.Printf("Init Server \n")

	max_send_bytes := (*mb)*1024*1024;
	bytesSent := 0


	message := make([]byte, max_send_bytes)  // Generate a message of PACKET_SIZE full of random information
	rand.Read(message)


	//Generate QUIC Config
	encoder := &quic.FecEncoder{Id: 0,
															Ratio: uint8(*fecRatio),
															Count: 0,
															FECData: nil,
															Timer: 3*time.Duration(*rtt)*time.Millisecond,
															N: *N,
															Dynamic: true,
															Delta: *delta,
															Target: *target}

	decoder := &quic.FecDecoder{Ratio: 0,
		Id: 0,
		Count: 0,
		MaxLength: 0}

	config := &quic.Config{
		Encoder: encoder,
		Decoder: decoder}

		traces.APP_TX_TraceInit( *id , *delta , *target , *N ,  3*time.Duration(*rtt)*time.Millisecond)

	//Listens on the given network address for QUIC conexion
	tlsconf := generateTLSConfig()
	listener, err := quic.ListenAddr(*ip, tlsconf, config)
	defer listener.Close()
	if err != nil {
		return
	}

	//Listens on the given network address for a TCP+TLS conexion
	tcpAddr, err := net.ResolveTCPAddr("tcp", *ip)
	if err != nil {
		return
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
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

	start := time.Now()
	end := time.Now();
	go func(){
		sess, _ := listener.Accept()
		start = time.Now()
		sess_chann <- sess
	}()

	go func(){
		conn, _ := tlsConn.Accept()
		start = time.Now()
		conn_chann <- conn
	}()

	select {
	case sess := <- sess_chann:    //QUIC session

		fmt.Println("Established QUIC connection")

		//stream, err := sess.AcceptStream()
		stream,err := sess.OpenStreamSync() ///Aparantly, if no data is transmitted it does not open any stream
		if err != nil {
			panic(err)
		}

		fmt.Printf("Server: Sending\n")
		bytesSent = 0

		n, err := stream.Write([]byte(message))
		bytesSent = bytesSent + n;
		end = time.Now();
		
		if (err != nil){
			fmt.Printf("Error \n")
			fmt.Print(err)
		}else{
			fmt.Printf("Without error\n")
		}

		packet_size := 1452//Maximum packet size
		buf := make([]byte, packet_size)
		n,_ = stream.Read(buf)
		fmt.Printf("-> %s", string(buf[:n]))
		stream.Close();
		sess.Close(nil);

	case conn := <- conn_chann:     //TCP Connection

		bytesSent = 0

		fmt.Println("Established TCP connection")
		fmt.Printf("Sever: Sending.... \n")

		n, err := conn.Write([]byte(message))
		bytesSent = bytesSent + n;
		end = time.Now()
		
		if (err != nil){
			fmt.Printf("Error \n")
			fmt.Print(err)
		}else{
			fmt.Printf("Without error\n")
		}
		
		packet_size := 1452//Maximum packet size
		buf := make([]byte, packet_size)
		n,_ = conn.Read(buf)
		fmt.Printf("-> %s", string(buf[:n]))
		conn.Close();

	}

	traces.PrintAPP(end.Sub(start), bytesSent, 0)

	t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
	thput := float64(bytesSent*8)/t
	fmt.Printf("Server - Sent: %d  bytes, Thput: %f Mbps, %f us\n", bytesSent, thput, t)
	//fmt.Printf("Start: %s, End: %s\n", start.String(), end.String())

	traces.CloseAll()
	time.Sleep(time.Second)
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
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}

