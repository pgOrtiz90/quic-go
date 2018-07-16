package main

import (
	"encoding/json"
	"fmt"
	"os"
	"io"
	"bufio"
	"sort"
	"net/http"
	hargo "github.com/mrichman/hargo"
	"time"
	"sync"
	"bytes"
	"strings"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

var wg sync.WaitGroup
var downloading_time time.Duration

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func newReader(r io.Reader) *bufio.Reader {

	buf := bufio.NewReader(r)
	b, err := buf.Peek(3)
	if err != nil {
		// not enough bytes
		return buf
	}
	if b[0] == 0xef && b[1] == 0xbb && b[2] == 0xbf {
		fmt.Printf("BOM detected. Skipping first 3 bytes of file. Consider removing the BOM from this file. See https://tools.ietf.org/html/rfc7159#section-8.1 for details.")
		buf.Discard(3)
	}
	return buf
}


func Decode(r *bufio.Reader) (hargo.Har, error) {
	dec := json.NewDecoder(r)
	var har hargo.Har
	err := dec.Decode(&har)

	check(err)

	// Sort the entries by StartedDateTime to ensure they will be processed
	// in the same order as they happened
	sort.Slice(har.Log.Entries, func(i, j int) bool {
		return har.Log.Entries[i].StartedDateTime < har.Log.Entries[j].StartedDateTime
	})

	return har, err
}

func httpRequest(addr string, client *http.Client) {
	defer wg.Done()
	start := time.Now()
	rsp, err := client.Get(addr)
	body := &bytes.Buffer{}
	_, err = io.Copy(body, rsp.Body)
	fmt.Printf(" %s, %d \n", addr, len(body.Bytes()))
	if err != nil {
		panic(err)
	}

	downloading_time += time.Now().Sub(start)
}


func main() {

	decoder := &quic.FecDecoder{Ratio: 0,
		Id: 0,
		Count: 0,
		MaxLength: 0}

	versions := protocol.SupportedVersions
	httpClient := &http.Client{
		Transport: &h2quic.RoundTripper{
			QuicConfig: &quic.Config{Versions: versions,  Decoder: decoder},
		},
	}

	//httpClient := http.Client{
	//	Transport: &http.Transport{
	//		Dial: (&net.Dialer{
	//			Timeout:   30 * time.Second,
	//			KeepAlive: 30 * time.Second,
	//		}).Dial,
	//		TLSHandshakeTimeout:   10 * time.Second,
	//		ResponseHeaderTimeout: 10 * time.Second,
	//		ExpectContinueTimeout: 1 * time.Second,
	//	},
	//	CheckRedirect: func(r *http.Request, via []*http.Request) error {
	//		r.URL.Opaque = r.URL.Path
	//		return nil
	//	},
	//}

	//harFile := "/Users/Pablo/Desktop/quic.clemente.io.har"
	harFile := "/Users/Pablo/Desktop/justwatch.har"

	file, err := os.Open(harFile)
	check(err)

	r := newReader(file)
	//u, err := url.Parse(c.String("u"))
	//ignoreHarCookies := c.Bool("ignore-har-cookies")

	check(err)

	//hargo.LoadTest(filepath.Base(harFile), r, workers, time.Duration(duration)*time.Second, *u, ignoreHarCookies)

	har, err := Decode(r)

	it := 0

	entry := har.Log.Entries[it]
	time_start1, err  := time.Parse(time.RFC3339,entry.StartedDateTime)
	check(err)
	wg.Add(1)
	go httpRequest(entry.Request.URL, httpClient)
	it = it + 1

	for it < (len(har.Log.Entries)){
		entry = har.Log.Entries[it]
		time_start2, err  := time.Parse(time.RFC3339,entry.StartedDateTime)
		check(err)
		elapsed := time_start2.Sub(time_start1)


		if (strings.Contains(entry.Request.URL, "localhost")){
			fmt.Printf(" %s \n", entry.Request.URL)
			wg.Add(1)
			go httpRequest(entry.Request.URL, httpClient)
		}


		time.Sleep(elapsed)

		it = it + 1
		time_start1 = time_start2
	}
	wg.Wait()

	fmt.Printf("Total Downloading Time: %d", int64(downloading_time/time.Millisecond))
}
