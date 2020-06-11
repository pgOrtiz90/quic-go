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



func Init(name string, debug bool) {
	logFileName = name
	debugging = debug
	run()
}

func Enable() {
	run()
}

func EnableForDebug() {
	debugging = true
	run()
}

func Disable() {
	close(closeQ)
	<-closeQdone
}

func DebugStart() {
	enabledMx.Lock()
	debugging = true
	if enabled {
		msgQ <- timestamp() + " Debug started"
	}
	enabledMx.Unlock()
}

func DebugEnd() {
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

func run() error {
	var msg string

	if logFileName == "" {
		logFileName = "rQUIC_log_" + timestamp()
	}
	logFile, err := os.OpenFile(logFileName+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return err
	}

	msg = timestamp() + " rQUIC logging initiated. Debug is "
	if debugging {
		msg += "enabled\n"
	} else {
		msg += "disabled\n"
	}
	logFile.Write([]byte(msg))

	msgQ = make(chan string, 4) // 2 goroutines at encoder, 1 at decoder, 1 for margin
	closeQ = make(chan struct{}, 0)
	closeQdone = make(chan struct{}, 0)

	countersReset()

	enabledMx.Lock()
	enabled = true
	enabledMx.Unlock()

	for {
		select {
		case msg = <-msgQ:
			logFile.Write([]byte(msg + "\n"))
		case <-closeQ:
			enabledMx.Lock()
			enabled = false
			enabledMx.Unlock()
			logFile.Write([]byte(CountersReport()))
			logFile.Write([]byte(timestamp() + " rQUIC logging finished.\n"))
			logFile.Close()
			close(msgQ)
			close(closeQdone)
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
	msg += fmt.Sprintf("    Source: %d", rxSrc)
	msg += fmt.Sprintf("    Coded : %d", txCod)
	msg += fmt.Sprintf("  Recovered: %d\n", rxRec)
	msg += "\\====================/\n"
	if IsEnabled() {
		msgQ <- msg
	}
	return msg
}

// Printf prepares the line for the log file. Log lines may come from concurrent
// goroutines. This function creates a string and sends it to a channel, from which
// another function takes it and and writes it to log file. A line break is always
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
	msgQ <- timestamp() + " " + fmt.Sprintf(format, v...)
}

func timestamp() string {
	return time.Now().Format("2006/01/02-15:04:05.000000000")
}
