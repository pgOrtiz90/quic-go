package main

// http://wprof.cs.washington.edu/spdy/tool/
// http://wprof.cs.washington.edu/tool/

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"github.com/lucas-clemente/quic-go/quictrace"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"strconv"
	"sync"
)

type binds []string

func (b binds) String() string {
	return strings.Join(b, ",")
}

func (b *binds) Set(v string) error {
	*b = strings.Split(v, ",")
	return nil
}

// Size is needed by the /demo/upload handler to determine the size of the uploaded file
type Size interface {
	Size() int64
}

// See https://en.wikipedia.org/wiki/Lehmer_random_number_generator
func generatePRData(l int) []byte {
	res := make([]byte, l)
	seed := uint64(1)
	for i := 0; i < l; i++ {
		seed = seed * 48271 % 2147483647
		res[i] = byte(seed)
	}
	return res
}

var tracer quictrace.Tracer

func init() {
	tracer = quictrace.NewTracer()
}

func exportTraces() error {
	traces := tracer.GetAllTraces()
	if len(traces) != 1 {
		return errors.New("expected exactly one trace")
	}
	for _, trace := range traces {
		f, err := os.Create("trace.qtr")
		if err != nil {
			return err
		}
		if _, err := f.Write(trace); err != nil {
			return err
		}
		f.Close()
		fmt.Println("Wrote trace to", f.Name())
	}
	return nil
}

type tracingHandler struct {
	handler http.Handler
}

var _ http.Handler = &tracingHandler{}

func (h *tracingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.handler.ServeHTTP(w, r)
	if err := exportTraces(); err != nil {
		log.Fatal(err)
	}
}

func setupHandler(www string, trace bool, finishTest chan struct{}) http.Handler {
	mux := http.NewServeMux()

	if len(www) > 0 {
		mux.Handle("/", http.FileServer(http.Dir(www)))
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Printf("Incoming: %#v\n", r)
			const maxSize = 1 << 30 // 1 GB
			num, err := strconv.ParseInt(strings.ReplaceAll(r.RequestURI, "/", ""), 10, 64)
			if err != nil || num <= 0 || num > maxSize {
				w.WriteHeader(400)
				return
			}
			w.Write(generatePRData(int(num)))
		})
	}

	mux.HandleFunc("/finish/test", func(w http.ResponseWriter, r *http.Request) {
		close(finishTest)
	})

	mux.HandleFunc("/demo", func(w http.ResponseWriter, r *http.Request) {
		var msg string
		msg += "  _______________________________\n"
		msg += " /\\                              \\\n"
		msg += "/++\\    __________________________\\\n"
		msg += "\\+++\\   \\ ************************/\n"
		msg += " \\+++\\   \\___________________ ***/\n"
		msg += "  \\+++\\   \\             /+++/***/\n"
		msg += "   \\+++\\   \\           /+++/***/\n"
		msg += "    \\+++\\   \\         /+++/***/\n"
		msg += "     \\+++\\   \\       /+++/***/\n"
		msg += "      \\+++\\   \\     /+++/***/\n"
		msg += "       \\+++\\   \\   /+++/***/\n"
		msg += "        \\+++\\   \\ /+++/***/\n"
		msg += "         \\+++\\   /+++/***/\n"
		msg += "          \\+++\\ /+++/***/\n"
		msg += "           \\+++++++/***/\n"
		msg += "            \\+++++/***/\n"
		msg += "             \\+++/***/\n"
		msg += "              \\+/___/\n\n"
		msg += "  https://www.asciiart.eu/art-and-design/escher\n"

		w.Write([]byte(msg))
	})

	if !trace {
		return mux
	}
	return &tracingHandler{handler: mux}
}

// Inspired by ListenAndServe defined in http3/server.go
func ListenAndServeHttpTcp(addr, certFile, keyFile string, handler http.Handler, ctx context.Context) error {
	// Load certs
	var err error
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	config := &tls.Config{
		Certificates: certs,
	}

	// Open the listeners
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	tcpConn, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return err
	}
	defer tcpConn.Close()

	tlsConn := tls.NewListener(tcpConn, config)
	defer tlsConn.Close()

	// Start the server
	httpServer := &http.Server{
		Addr:      addr,
		TLSConfig: config,
	}

	if handler == nil {
		handler = http.DefaultServeMux
	}
	httpServer.Handler = handler

	select {
	case <-ctx.Done():
		return nil
	default:
	}

	hErr := make(chan error)
	go func() {
		hErr <- httpServer.Serve(tlsConn)
	}()

	select {
	case err := <-hErr:
		if er := httpServer.Close(); er != nil {
			err = fmt.Errorf("%w; server closed with errors: " + er.Error(), err)
		}
		return err
	case <-ctx.Done():
		return httpServer.Close()
	}
}

func main() {

	bs := binds{}
	flag.Var(&bs, "bind", "bind to")
	www := flag.String("www", "", "www data")
	tcp := flag.Bool("tcp", false, "also listen on TCP")
	trace := flag.Bool("trace", false, "enable quic-trace")
	enableQlog := flag.Bool("qlog", false, "output a qlog (in the same directory)")

	//------------------ rQUIC settings
	logName := "server_web"
	prefix := "Server "

	//------------------ Server flags
	//mb := flag.Int("mb", 1, "File size in MiB")
	//timeOut := flag.String("timeout", "2m", "Server waiting for client timeout")
	confJson := flag.String("json", "server.json", "Path to json with rQUIC Conf.")
	certFile := flag.String("certFile", "cert.pem", "path to certificate file")
	keyFile := flag.String("keyFile", "priv.key", "path to key file")
	//------------------ Common flags
	ip := flag.String("ip", "localhost:6121", "IP:Port Address")
	rtrace := flag.Bool("rtrace", false, "Enable rQUIC traces")
	doLog := flag.Bool("log", false, "Enable rQUIC logging")
	debug := flag.Bool("debug", false, "Enable rQUIC debug logging (if true, ignores log)")
	info := flag.Bool("info", false, "Print informative messages")
	verbose := flag.Bool("v", false, "verbose (QUIC detailed logs)")
	wdir := flag.String("wdir", "", "Working directory. All relative paths take it as reference.")
	logFileName := flag.String("outputFile", logName, "Path to rtrace file")
	writeDefaultTestEnvironment := flag.Bool("writeDef", false, "Writes default rQUIC conf to json.")
	flag.Parse()

	//------------------ Digest flags, define tools

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
		// If rtrace file name is the default one, add a date-time stamp.
		logName += "_" + time.Now().Format(rLogger.TimeShort)
	} else {
		logName = *logFileName
	}
	if err := rLogger.Init(logName, *rtrace, *doLog, *debug); err != nil {
		rLogger.Logf(err.Error()) // Try to log the error if the logger could be initiated
		fmt.Println(err)
	} else {
		rLogger.Logf("Initiating")
	}

	// Print or log informative messages as specified by flags.
	//quiet := !*info
	//printInfo := func(format string, a ...interface{}) {
	//	msg := prefix + fmt.Sprintf(format, a...)
	//	if rLogger.IsLogging() {
	//		rLogger.Printf(msg)
	//	}
	//	if quiet {
	//		return
	//	}
	//	fmt.Println(msg)
	//}

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

	var err error

	// Read/Generate QUIC Config
	var rQC *rquic.Conf
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
	//config := &quic.Config{RQuic: rQC}
	rLogger.TakeNote("rQUIC Conf: " + rQC.String()) // rQC is not nil

	// Output string
	outputData := /*"rSimRes:" +*/ rQC.Overview()

	// QUIC logger
	logger := utils.DefaultLogger
	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
		//} else {
		//	logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	//------------------ Server configuration
	// defer profile.Start().Stop()
	//go func() {
	//	log.Println(http.ListenAndServe(*ip, nil))
	//}()
	// runtime.SetBlockProfileRate(1)

	//------------------

	if len(bs) == 0 {
		bs = binds{*ip}
	}

	var wg sync.WaitGroup

	// Close all servers
	servers := make([]io.Closer, 0, len(bs))
	finishTest := make(chan struct{})
	go func() {
		<-finishTest
		rLogger.Stop()
		fmt.Println("rSimRes:Srv:" + rQC.Overview() + "," + rLogger.CountersReport())
		return // All of them are killed in the script without errors
		//time.Sleep(2 * time.Second)
		var err error
		for _, s := range servers {
			if err = s.Close(); err != nil {
				printError("Server closed with errors: " + err.Error())
			}
		}
	}()

	var wwwPath string
	if *www == "" {
		if wwwPath, err = os.Getwd(); err != nil {
			printError("Could not get current directory: " + err.Error())
		}
	} else {
		wwwPath = *www
	}
	handler := setupHandler(wwwPath, *trace, finishTest)

	quicConf := &quic.Config{RQuic: rQC}
	if *trace {
		quicConf.QuicTracer = tracer
	}
	if *enableQlog {
		quicConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
			filename := fmt.Sprintf("server_%x.qlog", connID)
			f, err := os.Create(filename)
			if err != nil {
				log.Fatal(err)
			}
			log.Printf("Creating qlog file %s.\n", filename)
			return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
		})
	}

	// Load certs
	certs := make([]tls.Certificate, 1)
	certs[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		printError("Failed to load cert+key: " + err.Error())
		return
	}
	// We currently only use the cert-related stuff from tls.Config,
	// so we don't need to make a full copy.
	TLSConfig := &tls.Config{
		Certificates: certs,
	}

	wg.Add(len(bs))
	for _, b := range bs {
		go func() {
			var err error
			hSrv := &http.Server{
				Handler:   handler,
				Addr:      b,
				TLSConfig: TLSConfig,
			}
			if *tcp {
				servers = append(servers, hSrv)

				tcpAddr, err := net.ResolveTCPAddr("tcp", b)
				if err != nil {
					printError(err.Error())
					return
				}
				tcpConn, err := net.ListenTCP("tcp", tcpAddr)
				if err != nil {
					printError(err.Error())
					return
				}
				defer tcpConn.Close()
				tlsConn := tls.NewListener(tcpConn, TLSConfig)
				defer tlsConn.Close()

				err = hSrv.Serve(tlsConn)
			} else {
				server := http3.Server{
					Server:     hSrv,
					QuicConfig: quicConf,
				}
				servers = append(servers, &server)

				err = server.ListenAndServe()
			}
			if err != nil {
				printError(err.Error())
			}
			wg.Done()
		}()
	}

	wg.Wait()

	//------------------ Process output

	// failed to combine server closings and wg...
	wg.Add(1)
	go func() {
		time.Sleep(10 * time.Second)
		wg.Done()
	}()

	outputData += "," + rLogger.CountersReport()
	//fmt.Println("rSimRes:" + outputData)
	//fmt.Println("xxxx>", outputData)

	rLogger.Stop()

	wg.Wait()
}
