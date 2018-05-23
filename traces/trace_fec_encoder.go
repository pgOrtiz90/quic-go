package traces//Defines the tracing levels


import (
	"os"
	"time"
	"fmt"
)

type trace_fec_encoder struct{

	Ratio  uint8
	delta  float32
	target float32
	N		   uint32
	timer  time.Duration


	fileName string
	file *os.File
	timeStart  time.Time
}


func (t *trace_fec_encoder) OpenFile ( ){
	t.file,_ = os.Create(t.fileName)
	fmt.Fprintf(t.file, "Time \t Ratio \t Delta \t Target \t N \t T \n")
	return
}

func (t *trace_fec_encoder) Print( ratio uint8){
	t.Ratio = ratio
	fmt.Fprintf(t.file, "%f \t %d \t %f \t %f \t %d \t %f \n", time.Now().Sub(t.timeStart).Seconds(), ratio, t.delta, t.target, t.N, t.timer.Seconds())
}

func (t *trace_fec_encoder) close( ) {
	t.file.Close()
}