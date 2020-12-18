package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

const (
	//simCsvCliHdr = rquic.ConfOverviewHeader + ",Duration(ms),Received(B),Object," + rLogger.CountersReportHeader
	//simCsvCliDef = rquic.ConfOverviewEmpty + ",,,," /* output */ + rLogger.CountersReportEmpty
	TestURL = "pablo.io"
)

type JsonLoadPage struct {
	N_download_no_trigger float32      `json:"n_download_no_trigger"`
	Start_activity        string       `json:"start_activity"`
	Name                  string       `json:"name"`
	Objs                  []Object     `json:"objs"`
	Load_activity         float32      `json:"load_activity"`
	Deps                  []Dependency `json:"deps"`

	toDownload     map[string]*Object
	toComp         map[string]*Comp
	ownerOf        map[string]*Object
	downloadObject func(*Object) *dnldStats
	wg             sync.WaitGroup

	//mutex     sync.Mutex
	statsChan chan *dnldStats
	totTime   time.Duration
	cumTime   time.Duration
	bytes     int64
	objects   int
}

type Object struct {
	When_comp_start int      `json:"whencompstart"`
	Url             string   `json:"url"`
	Path            string   `json:"path"`
	Id              string   `json:"id"`
	Comps           []Comp   `json:"comps"`
	Host            string   `json:"host"`
	Download        Download `json:"download"`
}

type Comp struct {
	S_time float32 `json:"s_time"`
	Time   float32 `json:"time"`
	Id     string  `json:"id"`
	Type   int     `json:"type"`
	E_time float32 `json:"e_time"`

	nextDeps []*Dependency
}

type Download struct {
	S_time float32 `json:"s_time"`
	Type   string  `json:"type"`
	Id     string  `json:"id"`
}

type Dependency struct {
	A2   string  `json:"a2"`
	Time float32 `json:"time"`
	Id   string  `json:"id"`
	A1   string  `json:"a1"`
}

type dnldStats struct {
	duration time.Duration
	bytes    int64
}

func (j *JsonLoadPage) buildMaps() {
	var obj  *Object
	var comp *Comp
	var dep  *Dependency

	numDeps := len(j.Deps)

	j.statsChan = make(chan *dnldStats, 1+numDeps)

	j.toDownload = make(map[string]*Object)
	j.toComp = make(map[string]*Comp)

	// List of dependencies whose master comps haven't been found yet
	deps := make([]*Dependency, 0, numDeps)
	for d := range j.Deps {
		deps = append(deps, &j.Deps[d])
	}

	for o := range j.Objs {
		obj = &j.Objs[o]

		j.toDownload[obj.Download.Id] = obj

		// Complete dependency list for each comp
		for c := range obj.Comps {
			comp = &obj.Comps[c]
			comp.nextDeps = make([]*Dependency, 0, numDeps)
			j.toComp[comp.Id] = comp

			// Check all dependencies whose master comps haven't been found
			last := len(deps) - 1
			for d := last; d >= 0; d-- {
				dep = deps[d]
				if dep.A1 != comp.Id {
					// This dependency describes another comp
					continue
				}
				comp.nextDeps = append(comp.nextDeps, dep)

				// dep's comp found, remove it from deps
				if d != last {
					deps[d] = deps[last]
				}
				deps = deps[:last]
				last--
			}
		}
	}
	//j.wg.Add(numDlds)
}

func (j *JsonLoadPage) startActivity() {
	j.buildMaps()

	// Measurement routine
    measStop := make(chan struct{})
    measDone := make(chan struct{})
	go func() {
		for {
			select {
			case ods := <-j.statsChan:
				j.cumTime += ods.duration
				j.bytes += ods.bytes
				j.objects++
			case <-measStop:
				close(measDone)
				return
			}
		}
	}()

	j.wg.Add(1 /*1st obj*/ + len(j.Deps))
	start := time.Now()
	j.execute(j.Start_activity, start)

	j.wg.Wait()
	j.totTime = time.Now().Sub(start)
	close(measStop)
	<-measDone
}

//func (j *JsonLoadPage) process(activity string, startTime time.Time) {
//	var comp  Comp
//	var pTime time.Duration
//
//	defer j.wg.Done()
//	<-time.After(time.Now().Sub(startTime))
//
//	obj := j.ownerOf[activity]
//	if activity == obj.Download.Id {
//		j.downloadObject(obj)
//		if len(obj.Comps) == 0 {
//			return
//		}
//		comp = obj.Comps[0]
//	} else {
//		if len(obj.Comps) == 0 {
//			return
//		}
//		for _, c := range obj.Comps {
//			if c.Id == activity {
//				comp = c
//				break
//			}
//		}
//	}
//
//	for _, dep := range comp.nextDeps {
//		if dep.Time > 0 {
//			pTime = time.Duration(dep.Time * 1e6)
//		} else {
//			pTime = time.Duration(comp.Time * 1e6)
//		}
//		go j.process(dep.A2, time.Now().Add(pTime))
//	}
//}

func (j *JsonLoadPage) execute(activity string, startTime time.Time) {
	defer j.wg.Done()

	var comp  *Comp
	var startAfter time.Duration
	var endTime time.Time
	var ds *dnldStats

	// get comp
	obj, doDownload := j.toDownload[activity]
	if doDownload {
		<-time.After(time.Now().Sub(startTime))
		ds = j.downloadObject(obj)
		j.statsChan <- ds
		if len(obj.Comps) == 0 {
			return
		}
		comp = &obj.Comps[0]
		endTime = startTime.Add(ds.duration)
	} else {
		comp = j.toComp[activity]
		if len(comp.nextDeps) == 0 {
			return
		}
		endTime = startTime
	}

	for _, dep := range comp.nextDeps {
		if dep.Time > 0 {
			startAfter = time.Duration(dep.Time /*ms*/ * 1e6 /*ns/ms*/)
		} else {
			startAfter = time.Duration(comp.Time /*ms*/ * 1e6 /*ns/ms*/)
		}
		go j.execute(dep.A2, endTime.Add(startAfter))
	}
}



func main() {
	logName := "client_web"
	prefix := "Client "

	//------------------ Client flags
	webJson := flag.String("webJson", "www.flickr.com_.json", "web page JSON file path")
	keyLogFile := flag.String("keylog", "", "key log file")
	insecure := flag.Bool("insecure", false, "skip certificate verification")
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	letSrvInit := flag.Int("letSrvInit", 200, "Milliseconds to give server time to start")
	confJson := flag.String("json", "client.json", "Path to json with rQUIC Conf.")
	caCertPath := flag.String("caCertPath", "ca.pem", "path to CA certificate")
	dst := flag.String("dst", "https://test_server.io:6121", "URL:Port Address")
	//------------------ Common flags
	//ip := flag.String("ip", "localhost:6121", "IP:Port Address")
	trace := flag.Bool("trace", false, "Enable rQUIC traces")
	doLog := flag.Bool("log", false, "Enable rQUIC logging")
	debug := flag.Bool("debug", false, "Enable rQUIC debug logging (if true, ignores log)")
	info := flag.Bool("info", false, "Print informative messages")
	verbose := flag.Bool("v", false, "verbose (QUIC detailed logs)")
	wdir := flag.String("wdir", "", "Working directory. All relative paths take it as reference.")
	logFileName := flag.String("outputFile", logName, "Path to trace file")
	writeDefaultTestEnvironment := flag.Bool("writeDef", false, "Writes default rQUIC conf to json.")
	flag.Parse()

	//------------------ Digest flags, define tools

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
	//rQConfInUse := new(rquic.Conf)
	config := &quic.Config{RQuic: rQC/*onfInUse*/}
	rLogger.TakeNote("rQUIC Conf: " + rQC.String()) // rQC is not nil

	// No TCP in this experiment so far
	if *tcp {
		printError("WARNING: This client does not support TCP") // but eventually, it might
	}

	// QUIC logger
	logger := utils.DefaultLogger
	if *verbose {
		logger.SetLogLevel(utils.LogLevelDebug)
	//} else {
	//	logger.SetLogLevel(utils.LogLevelInfo)
	}
	logger.SetLogTimeFormat("")

	// Define pathBase, which might slightly differ from *dst
	pathBase := *dst

	//------------------ Client configuration

	var keyLog io.Writer
	if len(*keyLogFile) > 0 {
		f, err := os.Create(*keyLogFile)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		keyLog = f
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		log.Fatal(err)
	}
	//testdata.AddRootCA(pool)
	caCertRaw, err := ioutil.ReadFile(*caCertPath)
	if err != nil {
		panic(err)
	}
	if ok := pool.AppendCertsFromPEM(caCertRaw); !ok {
		panic("Could not add root ceritificate to pool.")
	}

	roundTripper := &http3.RoundTripper{
		TLSClientConfig: &tls.Config{
			RootCAs:            pool,
			InsecureSkipVerify: *insecure,
			KeyLogWriter:       keyLog,
		},
		QuicConfig: config,
	}
	client := &http.Client{
		Transport: roundTripper,
	}

	// Load dependencies.json
	errMsg := "Stopping. Failed to load web page JSON file: "
	jsonFile, err := os.Open(*webJson)
	if err != nil {
		printError(errMsg + err.Error())
		return
	}
	jsonBytes, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		printError(errMsg + err.Error())
		return
	}
	var deps JsonLoadPage
	err = json.Unmarshal(jsonBytes, &deps)
	if err != nil {
		printError(errMsg + err.Error())
		return
	}
	printInfo("LoadedJson:" + *webJson + "NumObjs:%d NumDeps:%d", len(deps.Objs), len(deps.Deps))

	// Add http request to deps
	deps.downloadObject = func(obj *Object) *dnldStats {
		path := pathBase + obj.Path

		start := time.Now()
		printInfo(obj.Download.Id + " ---- REQ >>> ---- " + start.Format("15:04:05.000000"))
		rsp, err := client.Get(path)
		if err != nil {
			panic("failed to request" + obj.Download.Id + ": " + err.Error())
		}
		end := time.Now()

		body := &bytes.Buffer{}
		lenRsp, err := io.Copy(body, rsp.Body)
		if err != nil {
			panic("failed to get response body for " + obj.Download.Id + ": " + err.Error())
		}
		printInfo(obj.Download.Id + " ---- <<< RSP ---- " + end.Format("15:04:05.000000") + " , %d Bytes", lenRsp)

		return &dnldStats{end.Sub(start), lenRsp}
	}

	// Simple way to send control messages to server
	heyServer := func(cmn string) string {
		if rsp, err := client.Get(pathBase + cmn); err != nil {
			printError("Failed to GET a response to " + cmn + ": " + err.Error())
			return ""
		} else if rsp != nil {
			body := &bytes.Buffer{}
			_, err = io.Copy(body, rsp.Body)
			return body.String()
		} else {
			printError("Got empty response to " + cmn)
			return ""
		}
	}

	time.Sleep(time.Duration(*letSrvInit) * time.Millisecond) // Let Server Init itself

	//------------------ Connection

	deps.startActivity()

	heyServer("/finish/test")

	//------------------ Process output

	rLogger.Stop()

	outputData := rQC.Overview()
	outputData += fmt.Sprintf(",%f,%f,%d,%d,",
		float64(deps.totTime) / 1e6, // Millisecond
		float64(deps.cumTime) / 1e6, // Millisecond
		deps.bytes,
		deps.objects,
	)
	outputData += rLogger.CountersReport()

	fmt.Println("rSimRes:Cli:" + outputData)

	return
}
