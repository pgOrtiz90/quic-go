package traces

import (
	"time"
	"fmt"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)


var trace traceLevels

//Defines the tracing levels
type traceLevels struct{
	//Congestion window trace
	cwnd_option bool
	cwnd *trace_cwnd

	//Stream Flow Control - QUIC trace
	streamFlowWindow_option bool
	//Connection Flow Control - QUIC trace
	connFlowWindow_option bool

	//Fec Module - trace
	fec_encoder_option bool
	fec_encoder *trace_fec_encoder

	//Application level trace
	application_option bool


	//File name for the output file -> fileName_LEVEL.tr
	//The system will generate as many files as levels are activate
	fileName string

	timeStart time.Time
}

func CWNDTraceInit (){

	if(trace.fec_encoder_option){
		fileName := fmt.Sprintf("%s_cwnd.tr", trace.fileName)

		tracer := &trace_cwnd{fileName, nil, trace.timeStart}
		tracer.OpenFile()
		trace.cwnd = tracer
	}
	return
}

func PrintCWND(cwnd protocol.ByteCount){
	if(trace.cwnd != nil){
		trace.cwnd.Print(cwnd)
	}
	return
}


func FecEncoderTraceInit ( ratio uint8 , delta float32, target float32, N uint32, T time.Duration){

	if(trace.fec_encoder_option){
		fileName := fmt.Sprintf("%s_fec_encoder.tr", trace.fileName)

		trace_encoder := &trace_fec_encoder{ratio, delta, target, N, T, fileName, nil, trace.timeStart}
		trace_encoder.OpenFile()
		trace.fec_encoder = trace_encoder
	}
	return
}

func PrintFecEncoder(ratio uint8){
	if(trace.fec_encoder != nil){
		trace.fec_encoder.Print(ratio)
	}
	return
}

func SetTraceFileName(fileName string){
	trace.timeStart = time.Now()
	trace.fileName = fileName
}

func SetFecEncoderTraceLevel(){
	trace.fec_encoder_option = true
}


func SetCWNDTraceLevel(){
	trace.cwnd_option = true
	CWNDTraceInit ()
}


func CloseAll(){
	if(trace.fec_encoder != nil){
		trace.fec_encoder.close()
	}

	if(trace.cwnd != nil){
		trace.cwnd.close()
	}
}



