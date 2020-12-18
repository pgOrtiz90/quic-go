// A very simple logger for rQUIC, independent from QUIC logger.
// Since the things that need to be logged are very specific and
// unique for each app, the logger can be defined as a module
// rather than a class.
package rLogger

import (
	"errors"
	"fmt"
	"os"
	"time"
	"sync"
	"strings"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

const TimeHuman = "2006/01/02-15:04:05.000000000"
const TimeOnly  = "15:04:05.000000000"
const TimeShort = "060102-150405"

const (
	LogLevelQuiet = iota
	LogLevelMin
	LogLevelDebug
)

const logFileNameDef = "rQUIC"

var trcMx, logMx sync.RWMutex
var tracing bool
var logLevel = LogLevelQuiet

var trcFile *os.File
var logFile *os.File

var timeRef time.Time

var msgQ, msgTQ chan string
var closeQ, closeTQ chan struct{}
var closeQdone, closeTQdone chan struct{}

var txSrc, txCod, txRet, rxSrc, rxCod, rxRec int64

func Init(name string, trace, log, debug bool) error {
	if !(trace || log || debug) {
		return nil
	}
	var errT, errL error

	// Adjust trace/log file name
	if name == "" {
		name = logFileNameDef + "_" + time.Now().Format(TimeShort)
	}

	// Create trace file
	if trace && !tracing {
		trcFile, errT = os.OpenFile(name+".csv", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if errT != nil {
			errT = fmt.Errorf("failed to open trace file %s: %w", name+".trace", errL)
			if !(log || debug) {
				tracing, logLevel = false, LogLevelQuiet
				return errT
			}
		} else {
			tracing = true
			msgTQ = make(chan string, 4) // 2 goroutines at encoder, 1 at decoder, 1 for margin
			closeTQ = make(chan struct{}, 0)
			closeTQdone = make(chan struct{}, 0)
			timeRef = time.Now()
			writeTrc(fmt.Sprintf("Reference time,%s\nMaxQuicPacketSize,%d\n",
				timeRef.Format(TimeHuman), protocol.MaxPacketSizeIPv4,
			))
			go runTrc()
		}
	}

	// Create log file
	if (log && logLevel < LogLevelMin) || (debug && logLevel < LogLevelDebug) {
		logFile, errL = os.OpenFile(name+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if errL != nil {
			logLevel = LogLevelQuiet
			errL = fmt.Errorf("failed to open log file %s: %w", name+".log", errL)
			if errT == nil {
				return errL
			}
			return errors.New("errors during rLogger initialization: " + errT.Error() + "; " + errL.Error())
		} else {
			if debug {
				logLevel = LogLevelDebug
			} else if log {
				logLevel = LogLevelMin
			}
			writeLog(fmt.Sprintf(time.Now().Format(TimeHuman)+" rQUIC logging initiated. Debug mode enabled:%t\n", debug))
			msgQ = make(chan string, 4) // 2 goroutines at encoder, 1 at decoder, 1 for margin
			closeQ = make(chan struct{}, 0)
			closeQdone = make(chan struct{}, 0)
			go runLog()
		}
	}

	return errT
}

func runTrc() {
	var line string
	for {
		select {
		case line = <-msgTQ:
			writeTrc(line)
		case <-closeTQ:
			//writeCountersReportTrace()
			trcMx.Lock()
			tracing = false
			trcMx.Unlock()
			if err := trcFile.Close(); err != nil {
				fmt.Printf("Failed to close trace file %s: %v\n", trcFile.Name(), err)
			}
			close(msgTQ)
			close(closeTQdone)
			return
		}
	}
}

func runLog() {
	var msg string
	for {
		select {
		case msg = <-msgQ:
			writeLog(msg)
		case <-closeQ:
			writeCountersReportLog()
			logMx.Lock()
			logLevel = LogLevelQuiet
			logMx.Unlock()
			writeLog( "\nrQUIC logging finished.\n")
			if err := logFile.Close(); err != nil {
				fmt.Printf("Failed to close log file %s: %v\n", logFile.Name(), err)
			}
			close(msgQ)
			close(closeQdone)
			return
		}
	}
}

const CountersReportHeader = "TxSrc,TxCod,ReTx,RxSrc,RxCod,Rec"
const CountersReportEmpty = ",,,,,"
func CountersReport() string { return fmt.Sprintf("%d,%d,%d,%d,%d,%d", txSrc, txCod, txRet, rxSrc, rxCod, rxRec) }

func writeCountersReportTrace() {
	if !IsTracing() {
		return
	}
	msg := "####\n"
	msg += fmt.Sprintf("TxSrc,%d\n", txSrc)
	msg += fmt.Sprintf("TxCod,%d\n", txCod)
	msg += fmt.Sprintf("ReTx,%d\n", txRet)
	msg += fmt.Sprintf("RxSrc,%d\n", rxSrc)
	msg += fmt.Sprintf("RxCod,%d\n", rxCod)
	msg += fmt.Sprintf("Rec,%d\n", rxRec)
	writeTrc(msg)
}

func writeCountersReportLog() {
	if !IsLogging() {
		return
	}
	msg := "\n/====================\\\n"
	msg += "  Transmitted:\n"
	msg += fmt.Sprintf("    Source: %d\n", txSrc)
	msg += fmt.Sprintf("    Coded:  %d\n", txCod)
	msg += fmt.Sprintf("    ReTx:   %d\n", txRet)
	msg += "  Received:\n"
	msg += fmt.Sprintf("    Source: %d\n", rxSrc)
	msg += fmt.Sprintf("    Coded : %d\n", rxCod)
	msg += fmt.Sprintf("  Recovered: %d\n", rxRec)
	msg += "\\====================/\n"
	writeLog(msg)
}

func writeTrc(line string) {
	if _, err := trcFile.Write([]byte(line)); err != nil {
		err = fmt.Errorf("rLogger failed to write to trace file: %w", err)
		Logf(err.Error())
		fmt.Println(err)
	}
}

func writeLog(msg string) {
	if msg[len(msg)-1] != '\n' {
		msg += "\n"
	}
	if _, err := logFile.Write([]byte(msg)); err != nil {
		//err = fmt.Errorf("rLogger failed to write to log file: %w", err)
		fmt.Println("rLogger failed to write to log file: " + err.Error())
	}
}

func Stop() {
	if IsTracing() {
		close(closeTQ)
		<-closeTQdone
	}
	if IsLogging() {
		close(closeQ)
		<-closeQdone
	}
}


func IsTracing() bool {
	trcMx.RLock()
	defer trcMx.RUnlock()
	return tracing
}

func IsLogging() bool {
	logMx.RLock()
	defer logMx.RUnlock()
	return logLevel >= LogLevelMin
}

func IsDebugging() bool {
	logMx.RLock()
	defer logMx.RUnlock()
	return logLevel >= LogLevelDebug
}

func IsDoingAnything() bool {
	return IsTracing() || IsLogging()
}

func MaybeIncreaseRxSrc() { rxSrc++ }
func MaybeIncreaseRxCod() { rxCod++ }
func MaybeIncreaseRxRec() { rxRec++ }
func MaybeIncreaseTxSrc() { txSrc++ }
func MaybeIncreaseTxCodN(n int) { txCod += int64(n) }
func MaybeIncreaseRxLstN(n int) { txRet += int64(n) }

func TraceHeader(a ...interface{}) {
	if !IsTracing() {
		return
	}
	format := strings.Repeat(",%v", len(a)) + "\n"
	msgTQ <- "Time(ns)" + fmt.Sprintf(format, a...)
}

// Trace writes any given data as a CSV line to the trace file.
func Trace(a ...interface{}) {
	if !IsTracing() {
		return
	}
	format := fmt.Sprintf("%d", time.Now().Sub(timeRef).Nanoseconds())
	format += strings.Repeat(",%v", len(a)) + "\n"
	msgTQ <- fmt.Sprintf(format, a...)
}

// Printf prepares the line for the log file. Log lines may come from concurrent
// goroutines. A line break is always
// added before writing the line to the log file.
//
// Printf is unaware of channel's state and may attempt to write to a closed channel!
//
// Use Printf with IsLogging() or IsDebugging() functions.
//   if rLogger.IsLogging() {
//       rLogger.Printf("The answer is %d", 42)
//   }
//
func Printf(format string, v ...interface{}) {
	msgQ <- time.Now().Format(TimeHuman) + " " + fmt.Sprintf(format, v...)
}

// Logf works exactly like Printf, but first checks if logging is enabled.
func Logf(format string, v ...interface{}) {
	if !IsLogging() {
		return
	}
	msgQ <- time.Now().Format(TimeHuman) + " " + fmt.Sprintf(format, v...)
}

// Debugf works exactly like Printf, but first checks if debugging is enabled.
func Debugf(format string, v ...interface{}) {
	if !IsDebugging() {
		return
	}
	msgQ <- time.Now().Format(TimeHuman) + " " + fmt.Sprintf(format, v...)
}

func TakeNote(msg string) {
	Logf(msg)
	if !IsTracing() {
		return
	}
	msg = fmt.Sprintf("%d,", time.Now().Sub(timeRef).Nanoseconds()) + msg
	l := len(msg)
	if msg[l-1] != '\n' { msg += "\n" }
	pre := strings.Repeat("-", l+4) + "\n"
	pos := strings.Repeat("-", utils.Max(1, l-4)) + "\n"
	msgTQ <- pre + msg + pos
}
