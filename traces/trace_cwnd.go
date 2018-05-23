package traces//Defines the tracing levels


import (
	"os"
	"time"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

type trace_cwnd struct{


	fileName string
	file *os.File
	timeStart  time.Time
}


func (t *trace_cwnd) OpenFile ( ){
	t.file,_ = os.Create(t.fileName)
	fmt.Fprintf(t.file, "Time \t Ratio \t Delta \t Target \t N \t T \n")
	return
}

func (t *trace_cwnd) Print( cwnd protocol.ByteCount){
	fmt.Fprintf(t.file, "%f \t %d \n", time.Now().Sub(t.timeStart).Seconds(), cwnd)
}

func (t *trace_cwnd) close( ) {
	t.file.Close()
}