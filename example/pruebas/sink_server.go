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
)

const addr = "127.0.0.1:4242"
const PACKET_SIZE = 2000

func main() {

	ip := flag.String("ip", "localhost:4242", "IP:Port Addres")
	flag.Parse()
	
	fmt.Printf("Init Server \n")
	
	//Listens on the given network address for QUIC conexion
	tlsconf := generateTLSConfig()
	listener, err := quic.ListenAddr(*ip, tlsconf, nil)
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
	
	bytesReceived := 0
	start := time.Now()
	
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
						
			stream, err := sess.AcceptStream()
			if err != nil {
				panic(err)
			}
			
		    fmt.Printf("Server accepted \n")
			
			buf := make([]byte, PACKET_SIZE)
					
			for{
				end := time.Now()
				stream.SetReadDeadline(time.Now().Add(10*time.Second))
				n, err := stream.Read(buf)
				if (err != nil){
					t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
					thput := float64(bytesReceived*8)/t
					fmt.Printf("Server - Received: %d  bytes, Thput: %f Mbps\n", bytesReceived, thput)
					return
				}
				bytesReceived = bytesReceived  + n
			}
			
		case conn := <- conn_chann:     //TCP Connection
			
			bytesReceived := 0
			start := time.Now()

			fmt.Println("Established TCP connection")
			
			buf := make([]byte, PACKET_SIZE)
			
			conn.SetReadDeadline(time.Now().Add(10*time.Second))
						
			for{
				end := time.Now()
				conn.SetReadDeadline(time.Now().Add(10*time.Second))
				n, err := conn.Read(buf)
				if (err != nil){
					t := float64(end.Sub(start)/1000) // Duration is in nanoseconds -> I get microseconds to get Mbps
					thput := float64(bytesReceived*8)/t
					fmt.Printf("Server - Received: %d  bytes, Thput: %f Mbps\n", bytesReceived, thput)
					return
				}
				bytesReceived = bytesReceived  + n
			}
		}	
	
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