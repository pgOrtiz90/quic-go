package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	//"time"
	//"sync"
	//"bytes"
	//"strings"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"flag"
	"github.com/lucas-clemente/quic-go/traces"
	"io/ioutil"
	"io"
	"os"
	"time"
	"bytes"
	"sync"
)

type JSON struct {
	N_download_no_trigger float32 `json:"n_download_no_trigger"`
	Start_activity 				string `json:"start_activity"`
	Name									string `json:"name"`
	Objs 									[]Objects  `json:"objs"`
	Load_activity 				float32 `json:"load_activity"`
	Deps 									[]Dependencies `json:"deps"`
}

type Objects struct {
	When_comp_start	int  `json:"whencompstart"`
	Url 						string  `json:"url"`
	Path 						string `json:"path"`
	Id 							string  `json:"id"`
	Comps 					[]Comps  `json:"comps"`
	Host  					string  `json:"host"`
	Download				Download  `json:"download"`
}

type Comps struct {
	S_time 	float32  `json:"s_time"`
	Time		float32  `json:"time"`
	Id			string  `json:"id"`
	Type 		int  `json:"type"`
	E_time 	float32  `json:"e_time"`
}

type Download struct {
	S_time  float32  `json:"s_time"`
	Type string  `json:"type"`
	Id  string  `json:"id"`
}



type Dependencies struct {
	A2  string  `json:"a2"`
	Time  float32  `json:"time"`
	Id string  `json:"id"`
	A1 string  `json:"a1"`
}




var wg sync.WaitGroup
var downloading_time time.Duration
var bytes_sent int
var objects int

var m sync.Mutex

func check2(e error) {
	if e != nil {
		fmt.Printf("NN\n")
		panic(e)
	}
}




func httpRequest(addr string, client *http.Client) {
	defer wg.Done()
	start := time.Now()

	if (client == nil){
		fmt.Printf("CLIENT NILLLL\n")
	}

	rsp, err := client.Get(addr)
	check2(err)
	defer rsp.Body.Close()

	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)

	fmt.Printf(" %s, %d \n", addr, len(body.Bytes()))
	if err != nil {
		panic(err)
	}

	m.Lock()
	bytes_sent += len(body.Bytes())
	downloading_time += time.Now().Sub(start)
	m.Unlock()
}


func main() {

	jsonFile  := flag.String("har","./www.google.com_.json", "Har FIle Path")
	trace := flag.String("trace","web_requests", "Trace File Name")
	id := flag.Uint("ID",0, "RUN IDENTIFIER")

	flag.Parse()


	traces.SetTraceFileName(*trace)
	//traces.SetFecEncoderTraceLevel()
	//traces.SetCWNDTraceLevel()
	traces.SetAPPTraceLevel()
	traces.APP_RX_TraceInit( *id)


	decoder := &quic.FecDecoder{Ratio: 0,
		Id: 0,
		Count: 0,
		MaxLength: 0}

	versions := protocol.SupportedVersions
 	h2QUIC := &h2quic.RoundTripper{
		QuicConfig: &quic.Config{Versions: versions,  Decoder: decoder},
	}

	httpClient := &http.Client{
		Transport: h2QUIC,
	}


	//json_File, err := os.Open("./www.google.com_.json")
	json_File, err := os.Open(*jsonFile)
	byteValue, _ := ioutil.ReadAll(json_File)
	fmt.Printf("%d \n",byteValue[0])
	check2(err)

	var json_ JSON
	json.Unmarshal(byteValue, &json_)

	fmt.Printf("Number Objects %d,  \n", len(json_.Objs))
	fmt.Printf("Number Dependencies %d,  \n", len(json_.Deps))


	entry := json_.Objs[0]


	fmt.Printf(" %s \n", entry.Path)

	var path bytes.Buffer
	path.WriteString("https://pablo.io:6121")
	path.WriteString(entry.Path)

	//fmt.Println(path.String())
	timing := entry.Download.S_time
	wg.Add(1)
	go httpRequest(path.String(), httpClient)

	for i:=1; i < len(json_.Objs); i++{

		entry = json_.Objs[i]


		if entry.Download.Id != ""{
			timing_aux := entry.Download.S_time
			elapsed := time.Duration(time.Duration(timing_aux - timing)*time.Millisecond)
			time.Sleep(elapsed)

			var path2 bytes.Buffer
			path2.WriteString("https://pablo.io:6121")
			path2.WriteString(entry.Path)

			//fmt.Printf("%d:--- %s \n",i,path2.String())

			wg.Add(1)
			go httpRequest(path2.String(), httpClient)
			objects +=1

			timing = timing_aux
		}

		wg.Wait()
	}

	fmt.Printf("Total Downloading Time: %d \n \n", int64(downloading_time/time.Millisecond))
	fmt.Printf("------------------------------\n")
	fmt.Printf("------------------------------\n")
	traces.PrintAPP(downloading_time, bytes_sent, objects)

	h2QUIC.Close()
}
