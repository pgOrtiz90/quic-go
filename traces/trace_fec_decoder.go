package traces//Defines the tracing levels


import (
	"os"
	"time"
	"fmt"
)

type trace_fec_decoder struct{

	FileName string
	file *os.File
	timeStart  time.Time

	blocks uint
	decoded uint
	fails uint
	redundant uint
}


func (t *trace_fec_decoder) OpenFile ( ){

	t.file, _ = os.OpenFile(t.FileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	fmt.Fprintf(t.file, "Blocks \t  Decoded \t  Fails \t  Redundant\t \n")
	t.blocks = 0
	t.decoded = 0
	t.fails = 0
	t.redundant = 0

	return
}

func (t *trace_fec_decoder) Store(blocks uint, decoded uint, fails uint, redundant uint){
	t.blocks = blocks
	t.decoded = decoded
	t.fails = fails
	t.redundant = redundant
}


func (t *trace_fec_decoder) Print ( ){
	fmt.Fprintf(t.file, " %d \t  %d \t %d\t %d \n",  t.blocks, t.decoded, t.fails, t.redundant)
	return
}

func (t *trace_fec_decoder) close( ) {
	t.file.Close()
}