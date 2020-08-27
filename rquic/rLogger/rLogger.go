// A very simple logger for rQUIC, independent from QUIC logger.
// Since the things that need to be logged are very specific and
// unique for each app, the logger can be defined as a module
// rather than a class.
package rLogger

import (
	"fmt"
	"os"
	"time"
	"sync"
)

var enabledMx sync.RWMutex
var enabled bool
var debugging bool

var msgQ chan string
var closeQ chan struct{}
var closeQdone chan struct{}

var logFileName string
var logFile *os.File

var txSrc, txCod, rxSrc, rxCod, rxRec int64

func Init(name string, debug bool)  {
	if IsEnabled() {
		return
	}
	logFileName = name
	debugging = debug
	prepareToRun()
	go run()
}

func Enable() {
	if IsEnabled() {
		return
	}
	prepareToRun()
	go run()
}

func EnableForDebug() {
	if IsEnabled() {
		DebugStart()
		return
	}
	debugging = true
	prepareToRun()
	go run()
}

func Disable() {
	if !IsEnabled() {
		return
	}
	close(closeQ)
	<-closeQdone
}

func DebugStart() {
	if IsDebugging() {
		return
	}
	enabledMx.Lock()
	debugging = true
	if enabled {
		msgQ <- timestamp() + " Debug started"
	}
	enabledMx.Unlock()
}

func DebugEnd() {
	if !IsDebugging() {
		return
	}
	enabledMx.Lock()
	debugging = false
	if enabled {
		msgQ <- timestamp() + " Debug finished"
	}
	enabledMx.Unlock()
}

func IsEnabled() bool {
	enabledMx.RLock()
	defer enabledMx.RUnlock()
	return enabled
}

func IsDebugging() bool {
	enabledMx.RLock()
	defer enabledMx.RUnlock()
	return enabled && debugging
}

func LogFileName(name string) {
	logFileName = name
}

func prepareToRun() error {
	var msg string

	if logFileName == "" {
		logFileName = "rQUIC_log_" + timestamp()
	}

	var err error
	logFile, err = os.OpenFile(logFileName+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		fmt.Println("Failed to open logFile " + logFileName)
		fmt.Println(err)
		return err
	}

	msg = timestamp() + " rQUIC logging initiated. Debug is "
	if debugging {
		msg += "enabled\n"
	} else {
		msg += "disabled\n"
	}
	writeLog(msg)

	msgQ = make(chan string, 4) // 2 goroutines at encoder, 1 at decoder, 1 for margin
	closeQ = make(chan struct{}, 0)
	closeQdone = make(chan struct{}, 0)

	countersReset()

	enabledMx.Lock()
	enabled = true
	enabledMx.Unlock()

	return nil
}

func run() error {
	var msg string
	for {
		select {
		case msg = <-msgQ:
			writeLog(msg)
		case <-closeQ:
			enabledMx.Lock()
			enabled = false
			enabledMx.Unlock()
			writeLog(CountersReport() + "\n rQUIC logging finished.\n")
			if err := logFile.Close(); err != nil {
				fmt.Println("Failed to close log file " + logFileName)
				fmt.Println(err)
			}
			close(msgQ)
			close(closeQdone)
			return nil
		}
	}
}

func MaybeIncreaseRxSrc() { if IsEnabled() { rxSrc++ } }
func MaybeIncreaseRxCod() { if IsEnabled() { rxCod++ } }
func MaybeIncreaseRxRec() { if IsEnabled() { rxRec++ } }
func MaybeIncreaseTxSrc() { if IsEnabled() { txSrc++ } }
func MaybeIncreaseTxCod() { if IsEnabled() { txCod++ } }
func MaybeIncreaseTxCodN(n int) { if IsEnabled() { txCod += int64(n) } }
func countersReset() { txSrc, txCod, rxSrc, rxCod, rxRec = 0, 0, 0, 0, 0 }

func CountersReport() string {
	msg := "\n/====================\\\n"
	msg += "  Transmitted:\n"
	msg += fmt.Sprintf("    Source: %d\n", txSrc)
	msg += fmt.Sprintf("    Coded:  %d\n", txCod)
	msg += "  Received:\n"
	msg += fmt.Sprintf("    Source: %d\n", rxSrc)
	msg += fmt.Sprintf("    Coded : %d\n", rxCod)
	msg += fmt.Sprintf("  Recovered: %d\n", rxRec)
	msg += "\\====================/\n"
	if IsEnabled() {
		msgQ <- msg
	}
	return msg
}

// Printf prepares the line for the log file. Log lines may come from concurrent
// goroutines. A line break is always
// added before writing the line to the log file.
//
// Printf is unaware of channel's state and may attempt to write to a closed channel!
//
// Use Printf with IsEnabled() or IsDebugging functions.
//   if rLogger.IsEnabled() {
//       rLogger.Printf("The answer is %d", 42)
//   }
//
func Printf(format string, v ...interface{}) {
	msgQ <- timestamp() + " " + fmt.Sprintf(format, v...) + "\n"
}

// Logf works exactly like Printf, but first checks if logging is enabled.
func Logf(format string, v ...interface{}) {
	if IsDebugging() {
		msgQ <- timestamp() + " " + fmt.Sprintf(format, v...) + "\n"
	}
}

// Debugf works exactly like Printf, but first checks if debugging is enabled.
func Debugf(format string, v ...interface{}) {
	if IsDebugging() {
		msgQ <- timestamp() + " " + fmt.Sprintf(format, v...) + "\n"
	}
}

func timestamp() string {
	return time.Now().Format("2006/01/02-15:04:05.000000000")
}

func writeLog(msg string) {
	l := len(msg)
	var errMsg string
	n, err := logFile.Write([]byte(msg))
	if err != nil {
		errMsg += err.Error() + "\n"
	}
	if n != l {
		errMsg += fmt.Sprintf("Wrote %d bytes out of %d\n", n, l)
	}
	if errMsg != "" {
		fmt.Printf("An error occurred while writing log message\nMESSAGE:\n%sERROR:\n%s",msg, errMsg)
	}
}
