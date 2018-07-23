package traces//Defines the tracing levels

import (
	"os"
	"time"
	"fmt"
)

type trace_app_receiver struct{

	// FILE
	FileName string
	file *os.File



	//Results
	id 				uint
	tx_t			time.Duration   // Transmission completion time
	tx_bytes  int   // Amount of bytes Transmitted
}


func (t *trace_app_receiver) OpenFile ( id uint){

	if _, err := os.Stat(t.FileName); os.IsNotExist(err) {
		t.file, _ = os.OpenFile(t.FileName, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
		fmt.Fprintf(t.file, " ID \t TX_TIME \t TX_BYTES \t OBJECTS \n")
	} else {
		t.file, _ = os.OpenFile(t.FileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}

	t.tx_t  = 0*time.Second
	t.tx_bytes = 0
	t.id = id
	return
}


func (t *trace_app_receiver) Print (tx_t time.Duration, tx_bytes int, objects int){
	fmt.Fprintf(t.file, " %d \t  %f \t %d \t %d \n",  t.id, tx_t.Seconds(), tx_bytes, objects)
	return
}

func (t *trace_app_receiver) close( ) {
	t.file.Close()
}