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
	fec_decoder_option bool
	fec_decoder *trace_fec_decoder

	//Application level trace
	application_option bool
	app_tx *trace_app_transmitter


	//File name for the output file -> fileName_LEVEL.tr
	//The system will generate as many files as levels are activate
	fileName string

	timeStart time.Time
}


func SetTraceFileName(fileName string){
	trace.timeStart = time.Now()
	trace.fileName = fileName
}


//CWN TRACER

func CWNDTraceInit (){

	if(trace.fec_encoder_option){
		fileName := fmt.Sprintf("%s_cwnd.tr", trace.fileName)

		tracer := &trace_cwnd{fileName, nil, trace.timeStart}
		tracer.OpenFile()
		trace.cwnd = tracer
	}
	return
}

func PrintCWND(cwnd protocol.PacketNumber){
	if(trace.cwnd != nil){
		trace.cwnd.Print(cwnd)
	}
	return
}


func SetCWNDTraceLevel(){
	trace.cwnd_option = true
	CWNDTraceInit ()
}


// FEC ENCODER TRACER

func FecEncoderTraceInit ( ratio uint8 , delta float32, target float32, N uint, T time.Duration){

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

func SetFecEncoderTraceLevel(){
	trace.fec_encoder_option = true
}


// FEC DECODER TRACER

func FecDecoderTraceInit( ){

	if(trace.fec_decoder_option){
		fileName := fmt.Sprintf("%s_fec_decoder.tr", trace.fileName)

		trace_decoder := &trace_fec_decoder{FileName: fileName}
		trace_decoder.OpenFile()
		trace.fec_decoder = trace_decoder
	}
	return
}

func  PrintFecDecoder ( ){
	if(trace.fec_decoder != nil){
		trace.fec_decoder.Print( )
	}
	}

func  StoreFecDecoder (blocks uint, decoded uint, fails uint, redundant uint){
	if(trace.fec_decoder != nil){
		trace.fec_decoder.Store(blocks , decoded , fails , redundant )
	}
}


func SetFecDecoderTraceLevel(){
	trace.fec_decoder_option = true
	FecDecoderTraceInit()
}

// APP TRACER

func APP_TX_TraceInit( id uint, delta float64, target float64, N uint, T time.Duration){
	if(trace.application_option){
		fileName := fmt.Sprintf("%s_app_tx.tr", trace.fileName)

		app_tx := &trace_app_transmitter{FileName: fileName}
		app_tx.OpenFile(id, delta, target, N, T )
		trace.app_tx = app_tx
	}
	return
}



func  PrintAPP ( tx_t time.Duration, tx_bytes int){
	if(trace.app_tx != nil){
		trace.app_tx.Print(tx_t, tx_bytes)
	}
}


func SetAPPTraceLevel(){
	trace.application_option = true
}


func CloseAll(){
	if(trace.fec_encoder != nil){
		trace.fec_encoder.close()
	}

	if(trace.cwnd != nil){
		trace.cwnd.close()
	}

	if(trace.fec_decoder != nil){
		trace.fec_decoder.close()
	}

	if(trace.app_tx != nil){
		trace.app_tx.close()
	}
}



