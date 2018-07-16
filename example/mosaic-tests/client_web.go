package main

import (
	"bytes"
	"flag"
	"io"
	"net/http"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/h2quic"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"golang.org/x/net/html"
	"fmt"
	"strings"
)

// Helper function to pull the href attribute from a Token
func getHref(t html.Token) (ok bool, href string) {
	// Iterate over all of the Token's attributes until we find an "href"
	for _, a := range t.Attr {
		if a.Key == "href" {
			href = a.Val
			ok = true
		}
	}

	// "bare" return will return the variables (ok, href) as defined in
	// the function definition
	return
}

func main() {
	verbose := flag.Bool("v", false, "verbose")
	tcp := flag.Bool("tcp", false, "Use a TCP/QUIC connection")
	tls := flag.Bool("tls", false, "activate support for IETF QUIC (work in progress)")
	flag.Parse()

	urls := flag.Args()

	if *verbose {
		utils.SetLogLevel(utils.LogLevelDebug)
	} else {
		utils.SetLogLevel(utils.LogLevelInfo)
	}
	utils.SetLogTimeFormat("")

	versions := protocol.SupportedVersions
	if *tls {
		versions = append([]protocol.VersionNumber{protocol.VersionTLS}, versions...)
	}

	if (*tcp != true){
		hclient := &http.Client{
			Transport: &h2quic.RoundTripper{
				QuicConfig: &quic.Config{Versions: versions},
			},
		}

		var wg sync.WaitGroup
		wg.Add(len(urls))
		for _, addr := range urls {
			utils.Infof("GET %s", addr)
			go func(addr string) {
				rsp, err := hclient.Get(addr)
				if err != nil {
					panic(err)
				}
				utils.Infof("Got response for %s: %#v", addr, rsp)

				//body := &bytes.Buffer{}
				//_, err = io.Copy(body, rsp.Body)
				//if err != nil {
				//	panic(err)
				//}
				//utils.Infof("Request Body:")
				//utils.Infof("%s", body.Bytes())

				b := rsp.Body
				z := html.NewTokenizer(b)

				for {
					tt := z.Next()

					switch {
					case tt == html.ErrorToken:
						// End of the document, we're done
						return
					case tt == html.StartTagToken:
						t := z.Token()

						// Check if the token is an <a> tag
						isAnchor := t.Data == "a"
						if !isAnchor {
							continue
						}

						// Extract the href value, if there is one
						ok, url := getHref(t)
						if !ok {
							continue
						}

						// Make sure the url begines in http**
						hasProto := strings.Index(url, "http") == 0
						if hasProto {
							fmt.Printf("URL: %s \n ", url)
						} else{
							fmt.Printf("URL: %s \n ", url)
					 }
					}
				}

				wg.Done()
			}(addr)
		}
		wg.Wait()
	}else{
		var wg sync.WaitGroup
		wg.Add(len(urls))
		for _, addr := range urls {
			utils.Infof("GET %s", addr)
			go func(addr string) {
				rsp, err := http.Get(addr)
				if err != nil {
					panic(err)
				}
				utils.Infof("Got response for %s: %#v", addr, rsp)

				body := &bytes.Buffer{}
				_, err = io.Copy(body, rsp.Body)
				if err != nil {
					panic(err)
				}
				utils.Infof("Request Body:")
				utils.Infof("%s", body.Bytes())
				wg.Done()
			}(addr)
		}
		wg.Wait()
	}
}
