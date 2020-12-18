package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/rquic"
	"github.com/lucas-clemente/quic-go/rquic/rLogger"
)



type netw struct { BW, RTT float64 }

type whoEnc struct{ Srv, Cli bool }

type encChecks struct {
	Schemes []string
	Overlaps,
	Redundancies,
	RatioValues,
	DynamicRatio,
	TPeriodsMS,
	RTTtoPeriodRatio,
	NumPeriods,
	GammaTarget,
	DeltaRatio []float64
}

const (
	// Net Srv Cli
	exOrderNet = iota
	exOrderSrv
	exOrderCli

	// Net Exp{Srv Cli}
	exOrderExp = exOrderSrv

	// Exp{Net Srv Cli}
	exOrderAll = exOrderNet
)

type testEnvirnoment struct {
	Desc             string
	Cmds             []string
	Networks         []*netw
	BulkFileSizes    []int
	LossRates        []float64
	RunTCP           bool
	WhoEncodes       []whoEnc
	Encoders         []*encChecks
	Iterations       float64
	IterBWNetw       float64
	FilterFile       string // relative path to the filter file
}

var testEnvironmentDefault = testEnvirnoment {
	Desc: "test",
	Cmds: []string{ // in execution order! i.e. net, srv, cli
		"./network.sh",
		"./server.sh",
		"./client.sh",
	},
	Networks: []*netw{
		{20, 25},
		{10, 100},
		{1.5, 400},
	},
	BulkFileSizes: []int{20, 20, 5},
	LossRates:     []float64{0, 1, 2, 3, 5},
	RunTCP:        false,
	WhoEncodes: []whoEnc{
		{true, false},
	},
	Encoders: []*encChecks{{
		Schemes:          []string{"SchemeXor"},
		Overlaps:         []float64{1},
		Redundancies:     []float64{1},
		RatioValues:      []float64{10},
		DynamicRatio:     []float64{1},
		TPeriodsMS:       []float64{},
		RTTtoPeriodRatio: []float64{3},
		NumPeriods:       []float64{3},
		GammaTarget:      []float64{0.01},
		DeltaRatio:       []float64{0.33},
	}},
	Iterations: 100,
	IterBWNetw: 10,
}

func TestEnvironmentDefault() *testEnvirnoment {
	te := testEnvironmentDefault
	return &te
}



const (
	protoBitSRV = 0x01
	protoBitCLI = 0x02
	protoBitFLL = 0x03
	protoBitTCP = 0x04
)

type protocolInfo byte

func (p *protocolInfo) tcp() bool       { return *p&protoBitTCP > 0 }
func (p *protocolInfo) quic() bool      { return *p&protoBitFLL == 0 }
func (p *protocolInfo) rQuicFull() bool { return *p&protoBitFLL == protoBitFLL }
func (p *protocolInfo) rQuicSrv() bool  { return *p&protoBitFLL == protoBitSRV }
func (p *protocolInfo) rQuicCli() bool  { return *p&protoBitFLL == protoBitCLI }

func newProtocolInfo(we []whoEnc, tcp bool) []protocolInfo {
	var b protocolInfo
	pi := make([]protocolInfo, 0, 5)
	if tcp {
		pi = append(pi, protoBitTCP)
	}
	for _, w := range we {
		b = 0
		if w.Srv { b |= protoBitSRV }
		if w.Cli { b |= protoBitCLI }
		pi = append(pi, b)
	}
	return pi
}



type OutputFilter struct {
	Filters [][]string
}

func NewOutputFilter(f string) (*OutputFilter, error) {
	filtersDef := [][]string{
		{"Waf: Entering directory"},
		{"Waf: Leaving directory"},
		{"Build commands will be stored in "},
		{"'build' finished successfully"},
		{"Command ", "terminated with signal SIGTERM"}, // Because I have SIGTERMed it! Pesado...
	}
	of := new(OutputFilter)
	if fltRaw, err := ioutil.ReadFile(f); err != nil {
		return &OutputFilter{filtersDef}, fmt.Errorf("failed to OPEN output filter json: %w", err)
	} else {
		if err = json.Unmarshal(fltRaw, of); err != nil {
			return &OutputFilter{filtersDef}, fmt.Errorf("failed to IMPORT test specification: %w", err)
		}
	}
	return of, nil
}

func (of *OutputFilter) match(line string) bool {
FilterScan:
	for _, filter := range of.Filters {
		for _, block := range filter {
			if !strings.Contains(line, block) {
				continue FilterScan
			}
			// Text patterns in the filter are ordered
			line = strings.Join(strings.Split(line, block)[1:], block)
		}
		// The line contained all blocks in the right order, full match
		return true
	}
	return false
}

func (of *OutputFilter) filter(txt *string) {
	lines := strings.Split(*txt, "\n")
	linesRmn := make([]string, 0, len(lines))

	for _, line := range lines {
		if !of.match(line) {
			linesRmn = append(linesRmn, line)
		}
	}

	*txt = strings.Join(linesRmn, "\n")
}



const (
	perspectiveServer = 0
	perspectiveClient = 1

	logLNet = iota
	logLPrt
	logLCC1
	logLCC2

	simCsvCliHdr = rquic.ConfOverviewHeader + ",Throughput(Mbps),Duration(us),Received(B)," + rLogger.CountersReportHeader
	simCsvCliDef = rquic.ConfOverviewEmpty + ",,,," /* output */ + rLogger.CountersReportEmpty
	simCsvSrvHdr = rquic.ConfOverviewHeader + ",Throughput(Mbps),Duration(us),Sent(B),Message(B)," + rLogger.CountersReportHeader
	simCsvSrvDef = rquic.ConfOverviewEmpty + ",,,,," + rLogger.CountersReportEmpty
	simCsvHeader = "SimDur,BW(Mbps),RTT(us),LossRate(%),ITER" +
		",SERVER:," + simCsvSrvHdr + ",CLIENT:," + simCsvCliHdr + "\n"
	simCsvMsgStart = "rSimRes:"
	simCsvMsgSrv   = "Srv:"
	simCsvMsgCli   = "Cli:"
	simCsvMsgEnd   = "\n"
)

type assistant struct {
	Network      *netw
	BulkFileSize int
	LossRate     float64
	protocolInfo protocolInfo
	Encoders     [2]*rquic.ConfJson

	mu          sync.Mutex
	fileLog     *os.File
	fileCsv     *os.File
	cmdSrv      *exec.Cmd
	execute     func()
	netwLaunch  func() func()
	outBufErr   *bytes.Buffer
	outBufCmds  []*bytes.Buffer
	outBufNames []string
	filter      func(*string)
	manageNet   bool
	manageSrv   bool
	infoLevel   int
	launchTime  time.Time

	testEnv     *testEnvirnoment
	iterations  int64
	itersRemain int64
	iterLocal   int64
	perspective int       // 0 - server; 1 - client
	perspStr    [2]string // only 2 options
}

func hireAssistant(logName string, testEnv *testEnvirnoment) (*assistant, error) {
	var err error

	// Open log files
	if logName == "" {
		logName = "sim_campaign_" + time.Now().Format(rLogger.TimeShort)
	}
	fileLog, errL := os.OpenFile(logName+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	fileCsv, errC := os.OpenFile(logName+".csv", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if errC == nil {
		if st, er := fileCsv.Stat(); er == nil {
			// Write CSV header only once
			if st.Size() == 0 {
				_, errC = fileCsv.WriteString(simCsvHeader)
			}
		}
	}
	if errL == nil {
		err = errC
	} else if errC != nil {
		err = fmt.Errorf("%v; %v", errL, errC)
	}
	if err != nil {
		err = fmt.Errorf("errors during sim_campaign log creation: %w", err)
	}

	a := &assistant{
		fileLog:     fileLog,
		fileCsv:     fileCsv,
		outBufErr:   new(bytes.Buffer),
		launchTime:  time.Now(),
		Network:     new(netw),
		Encoders: [2]*rquic.ConfJson{
			&rquic.ConfJson{CConfJson: &rquic.CConfJson{}},
			&rquic.ConfJson{CConfJson: &rquic.CConfJson{}},
		},
		testEnv:     testEnv,
		iterations:  int64(testEnv.Iterations),
		itersRemain: int64(testEnv.Iterations),
		perspStr:    [2]string{"server", "client"},
	}

	// Create buffers for capturing commands' outputs.
	numCmds := len(testEnv.Cmds)
	switch numCmds {
	case 1:
		a.outBufNames = []string{"EXP"} // Server, client and the network are launched with one command
		a.netwLaunch = func() func() {return func(){}}
		a.execute = a.runExperiment
	case 2:
		a.outBufNames = []string{"NET", "SnC"} // Server and client are launched in one command
		a.netwLaunch = a.networkLaunch
		a.execute = a.runExperiment
	default: // 3, ignore extra commands
		a.outBufNames = []string{"NET", "SRV", "CLI"}
		a.netwLaunch = a.networkLaunch
		a.execute = a.runSRVandCLI
	}
	a.outBufCmds = make([]*bytes.Buffer, numCmds)
	for i := range a.outBufCmds {
		a.outBufCmds[i] = new(bytes.Buffer)
	}

	// Load output filters (for very known and redundant outputs)
	if testEnv.FilterFile == "" {
		a.filter = func(_ *string) {return}
	} else {
		if of, err := NewOutputFilter(testEnv.FilterFile); err != nil {
			fmt.Errorf("could not load output filters %s: %w", testEnv.FilterFile, err)
			a.filter = func(_ *string) {return}
		} else {
			a.filter = of.filter
		}
	}

	return a, err
}

func (a *assistant) writeConf(perspective int) bool /* failed to write json */ {
	fileName := a.perspStr[perspective] + ".json"
	if err := a.Encoders[perspective].WriteJson(fileName); err != nil {
		a.outBufErr.WriteString("Could not write " + fileName + ": " + err.Error() + "\n")
		return true
	}
	return false
}

func (a *assistant) iterInfo() (str string) {
	const prefix = "--- "

	str = "\n=== " + time.Now().Format(rLogger.TimeHuman) + " \""+a.testEnv.Desc+"\"" +
		" Iterations: " + fmt.Sprintf("%d/%d\n", a.iterations-a.itersRemain+a.iterLocal, a.iterations)
	str += prefix + fmt.Sprintf("BW: %v Mbps, RTT: %v ms, File Size: %dMB, Loss Rate: %v%%\n",
		a.Network.BW, a.Network.RTT, a.BulkFileSize, a.LossRate,
	)
	if a.infoLevel == logLNet {
		return
	}

	str += prefix
	if a.protocolInfo.tcp() {
		return str + "TCP\n"
	} else if a.protocolInfo.quic() {
		return str + "QUIC\n"
	} else {
		str += "rQUIC"
		if !a.protocolInfo.rQuicFull() {
			str += " only " + a.perspStr[a.perspective] + " encodes"
		}
	}
	str += "\n"
	if a.infoLevel == logLPrt {
		return
	}

	if a.protocolInfo.rQuicSrv() {
		str += prefix + "Server Encoder: " + a.Encoders[perspectiveServer].Overview(true) + "\n"
	} else if a.protocolInfo.rQuicCli() {
		return str + prefix + "Client Encoder: " + a.Encoders[perspectiveClient].Overview(true) + "\n"
	}
	if a.infoLevel == logLCC1 || !a.protocolInfo.rQuicFull() {
		return
	}

	return str + prefix + "Client Encoder: " + a.Encoders[perspectiveClient].Overview(true) + "\n"
}

func (a *assistant) iterate() {

	var i int
	var iterLocalLimit int64
	var netwStop func()

	protocolInfoSlice := newProtocolInfo(a.testEnv.WhoEncodes, a.testEnv.RunTCP)
	for N := int64(a.testEnv.IterBWNetw); a.itersRemain > 0; a.itersRemain -= N {
		iterLocalLimit = utils.MinInt64(N, a.itersRemain)
		for i, a.Network = range a.testEnv.Networks {
			a.BulkFileSize = a.testEnv.BulkFileSizes[i]
			for _, a.LossRate = range a.testEnv.LossRates {
				a.infoLevel = logLNet
				netwStop = a.netwLaunch()
				for a.iterLocal = 0; a.iterLocal < iterLocalLimit; a.iterLocal++ {
					for _, a.protocolInfo = range protocolInfoSlice {
						a.infoLevel = logLPrt
						if a.protocolInfo.tcp() {
							a.execute()
						} else if a.protocolInfo.quic() {
							for p, e := range a.Encoders {
								e.EnableEncoder = false
								e.EnableDecoder = false
								a.writeConf(p)
							}
							a.execute()
						} else {
							a.infoLevel = logLCC1
							a.iterateCConf(false)
						}
					}
				}
				netwStop()
			}
		}
	}
}

// iterateCConf creates a CConfJson for all possible parameter combinations
// provided by test environment a.testEnv .
//   asClient = true forces iterations over client's CConf.
//   With asClient = false, iterateCConf first tries to iterate over server's
//   encoder, and then over the client's one.
func (a *assistant) iterateCConf(asClient bool) {

	// Iterate over client's or server's encoding parameters?
	// Should there be other iterations?
	var doIterateAnotherCConf bool
	if a.protocolInfo.rQuicSrv() && !asClient {
		a.perspective = perspectiveServer
		doIterateAnotherCConf = a.protocolInfo.rQuicCli()
	} else if a.protocolInfo.rQuicCli() {
		a.perspective = perspectiveClient
	} else {
		return
	}

	// Complete the encoders and pick the right one.
	e := a.testEnv.Encoders[a.perspective]
	c := a.Encoders[a.perspective]
	c.EnableEncoder = true
	c.EnableDecoder = a.protocolInfo.rQuicFull()
	a.Encoders[1-a.perspective] = c.Complementary()
	if !c.EnableDecoder { a.writeConf(1-a.perspective) }
	cc := c.CConfJson

	// Prepare DynRatioPers for iteration.ratios
	DynRatioPers := make([]float64, len(e.RTTtoPeriodRatio) + len(e.TPeriodsMS))
	for i, RTTtoPeriodRatio := range e.RTTtoPeriodRatio {
		DynRatioPers[i] = a.Network.RTT * RTTtoPeriodRatio
	}
	copy(DynRatioPers[len(e.RTTtoPeriodRatio):], e.TPeriodsMS)

	// Iterate
	for _, cc.Scheme = range e.Schemes {
		for _, cc.Overlap = range e.Overlaps {
			for _, cc.Reduns = range e.Redundancies {
				for _, cc.RatioVal = range e.RatioValues {
					for _, cc.Dynamic = range e.DynamicRatio {
						for _, cc.TPeriodMS = range DynRatioPers {
							for _, cc.NumPeriods = range e.NumPeriods {
								for _, cc.GammaTarget = range e.GammaTarget {
									for _, cc.DeltaRatio = range e.DeltaRatio {
										if a.writeConf(a.perspective) /* failed to write json */ {
											continue
										}
										if doIterateAnotherCConf {
											a.infoLevel = logLCC2
											a.iterateCConf(true)
											continue
										}
										a.execute()
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func (a *assistant) networkLaunch() func() {

	cmdNet := a.buildCommand(exOrderNet,
		//fmt.Sprintf("-bw=%v", a.Network.BW),
		//fmt.Sprintf("-rtt=%v", a.Network.RTT),
		//fmt.Sprintf("-lossRate=%v", a.LossRate/100),
		fmt.Sprintf("-bw=%v -rtt=%v -lossRate=%v", a.Network.BW, a.Network.RTT, a.LossRate/100),
	)

	if err := cmdNet.Start(); err != nil {
		a.outBufErr.WriteString("Network initialization error: " + err.Error() + "\n")
	}

	return func() {
		if err := cmdNet.Process.Signal(os.Interrupt); err != nil {
			a.outBufErr.WriteString("Failed to stop network: " + err.Error() + "\n")
			return
		}
		if _, err := cmdNet.Process.Wait(); err != nil {
			a.outBufErr.WriteString("Failed to stop network: " + err.Error() + "\n")
		}
	}
}

func (a *assistant) runSRVandCLI() {
	var err error
	defer func() {
		if err != nil {
			a.outBufErr.WriteString("Experiment execution error: " + err.Error() + "\n")
		}
		a.report()
	}()

	// Start server
	cmdSrv := a.buildCommand(exOrderSrv, fmt.Sprintf("-mb=%d", a.BulkFileSize))

	if err = cmdSrv.Start(); err != nil {
		err = fmt.Errorf("failed to start server: %w", err)
		return
	}

	// Run client
	cmdCli := a.buildCommand(exOrderCli, fmt.Sprintf("-mb=%d", a.BulkFileSize))
	if a.protocolInfo.tcp() {
		cmdCli.Args = append(cmdCli.Args, "-tcp")
	}

	if err = cmdCli.Run(); err != nil {
		err = fmt.Errorf("failed to start client: %w", err)
		if er := cmdSrv.Process.Signal(os.Interrupt); er != nil {
			err = errors.New(err.Error() + "; failed to kill server process: " + er.Error())
		}
		return
	}

	// Wait for the server if it is still running
	if err = cmdSrv.Wait(); err != nil {
		err = fmt.Errorf("failed to wait for the server: %w", err)
	}
}

func (a *assistant) runExperiment() {
	cmdExp := a.buildCommand(exOrderExp, fmt.Sprintf("-mb=%d", a.BulkFileSize))
	if a.protocolInfo.tcp() {
		cmdExp.Args = append(cmdExp.Args, "-tcp")
	}
	if err := cmdExp.Run(); err != nil {
		a.outBufErr.WriteString("Experiment execution error: " + err.Error() + "\n")
	}
	a.report()
}

func (a *assistant) buildCommand(exInd int, args ...string) *exec.Cmd {
	cmd := exec.Command(a.testEnv.Cmds[exInd])
	if len(args) > 0 {
		cmd.Args = append(cmd.Args, args...)
	}
	//fmt.Println(strings.Join(cmd.Args, " "))
	a.outBufCmds[exInd].Reset()
	cmd.Stdout = a.outBufCmds[exInd]
	cmd.Stderr = a.outBufCmds[exInd]
	return cmd
}

func (a *assistant) report() {
	var report, msg, rep string
	var repSrv, repCli = simCsvSrvDef, simCsvCliDef

	now := time.Now()
	csvLine := fmt.Sprintf("%s,%v,%v,%v,%d", now.Sub(a.launchTime), a.Network.BW, a.Network.RTT, a.LossRate, a.iterations-a.itersRemain+a.iterLocal)
	a.launchTime = now

	for i, b := range a.outBufCmds {
		if msg = b.String(); len(msg) == 0 {
			continue
		}

		// Extract output from cmd buffers
		for strings.Contains(msg, simCsvMsgStart) {
			rep = strings.Split(msg, simCsvMsgStart)[1]
			rep = strings.Split(rep, simCsvMsgEnd)[0]
			if strings.HasPrefix(rep, simCsvMsgSrv) {
				repSrv = rep[len(simCsvMsgSrv):]
				msg = strings.Join(strings.Split(msg, simCsvMsgStart+rep+simCsvMsgEnd), "")
			} else if strings.HasPrefix(rep, simCsvMsgCli) {
				repCli = rep[len(simCsvMsgCli):]
				msg = strings.Join(strings.Split(msg, simCsvMsgStart+rep+simCsvMsgEnd), "")
			}
		}

		// The filter is for ns3 spam, no need to apply it to other buffers
		if i == exOrderNet && len(msg) > 0 {
			a.filter(&msg)
		}

		if len(msg) > 0 {
			report += "\n------- " + a.outBufNames[i] + " ---------------------\n" + msg
		}

		b.Reset()
	}

	csvLine += "," + a.testEnv.Desc + "," + repSrv
	csvLine += "," + a.testEnv.Desc + "," + repCli
	if _, err := a.fileCsv.WriteString(csvLine + "\n"); err != nil {
		a.outBufErr.WriteString("CSV log error: " + err.Error() + "\nUnwritten line: " + csvLine + "\n")
	}

	// Errors should be read once a.outBuffErr is left alone
	if msg = a.outBufErr.String(); len(msg) > 0 {
		report = "\n------- ERR ---------------------\n" + msg + report // Put errors on top of the report
		a.outBufErr.Reset()
	}

	if len(report) == 0 {
		return
	}
	report = a.iterInfo() + report
	if _, err := a.fileLog.WriteString(report); err != nil {
		fmt.Println("Failed to write report: " + err.Error() + "\nThe report:\n" + report)
	}
}



func loadTestEnv(name string, testEnv *testEnvirnoment) *testEnvirnoment {
	if testEnv == nil {
		// Read testEnvironment from json if possible, or take the default values.
		if name == "" {
			testEnv = TestEnvironmentDefault()
		} else {
			if testEnvRaw, err := ioutil.ReadFile(name); err != nil {
				err = fmt.Errorf("failed to OPEN test specification json: %w", err)
				testEnv = TestEnvironmentDefault()
			} else if len(testEnvRaw) == 0 { // file read, but it was empty
				testEnv = TestEnvironmentDefault()
			} else {
				if err = json.Unmarshal(testEnvRaw, &testEnv); err != nil {
					err = fmt.Errorf("failed to IMPORT test specification: %w", err)
					testEnv = TestEnvironmentDefault()
				}
			}
		}
	}

	// Complete encChecks
	if testEnv.Encoders[0] == nil {
		testEnv.Encoders[0] = testEnvironmentDefault.Encoders[0]
	}
	if len(testEnv.Encoders) == 1 {
		testEnv.Encoders = append(testEnv.Encoders, nil)
	}
	var encodersEqual bool
	if testEnv.Encoders[1] == nil {
		testEnv.Encoders[1] = testEnv.Encoders[0]
		encodersEqual = true
	}
	testEnv.Encoders = testEnv.Encoders[:2] // Only 2 endpoints.

	// Depending on the network type, we will send more or less data.
	// BulkFileSizes has to be the same size as Networks.
	// If BulkFileSizes is bigger, the exceeding values will not be evaluated.
	if d := len(testEnv.Networks) - len(testEnv.BulkFileSizes); d > 0 {
		for v := testEnv.BulkFileSizes[len(testEnv.BulkFileSizes)-1]; d > 0; d-- {
			testEnv.BulkFileSizes = append(testEnv.BulkFileSizes, v)
		}
	}

	// Check that coding schemes are correct
	for _, en := range testEnv.Encoders {
		w := 0
		for _, sc := range en.Schemes {
			if _, ok := rquic.SchemesReader[sc]; ok {
				en.Schemes[w] = sc
				w++
			}
		}
		en.Schemes = en.Schemes[:w]
		if encodersEqual {
			break
		}
	}

	// Iterations between the change of network should be between 1 and testEnv.Iterations
	if testEnv.IterBWNetw < 1 {
		testEnv.IterBWNetw = 1
	} else if testEnv.IterBWNetw > testEnv.Iterations || len(testEnv.Cmds) == 1 /* no netw mngt */ {
		testEnv.IterBWNetw = testEnv.Iterations
	}

	return testEnv
}

func main() {
	wdir := flag.String(
		"wdir",
		"",
		"Working directory. Used for writing output log and reading json file (relative path).",
	)
	tstEnvJson := flag.String(
		"json",
		"TestEnvironment.json",
		"Path (absolute or relative to wdir) to json with test configuration.",
	)
	writeDefaultTestEnvironment := flag.Bool(
		"writeDef",
		false,
		"Writes default test configuration to json specified by json file.",
	)
	logName := flag.String(
		"logName",
		"",
		"Name of the log file",
	)
	flag.Parse()

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

	var testEnv *testEnvirnoment

	if *writeDefaultTestEnvironment {
		testEnv = TestEnvironmentDefault()
		if defValues, err := json.MarshalIndent(testEnvironmentDefault, "", "    "); err != nil {
			fmt.Println("Failed to marshal json with default test environment: " + err.Error())
		} else if err := ioutil.WriteFile(*tstEnvJson, defValues, 0644); err != nil {
			fmt.Println("Failed to write default test environment: " + err.Error())
		}
	}

	testEnv = loadTestEnv(*tstEnvJson, testEnv)
	//fmt.Printf("%+v\n", testEnv)
	//for _, nw := range testEnv.Networks {
	//	c
	//}
	//for _, en := range testEnv.Encoders {
	//	fmt.Printf("%+v\n", en)
	//}
	//return

	a, err := hireAssistant(*logName, testEnv)
	if err != nil {
		fmt.Println("Assistant hired with errors: " + err.Error())
	}
	if a == nil {
		return
	}

	a.iterate()
	if err := a.fileLog.Close(); err != nil {
		fmt.Printf("Error when closing log file: " + err.Error())
	}
	if err := a.fileCsv.Close(); err != nil {
		fmt.Printf("Error when closing CSV file: " + err.Error())
	}
}
