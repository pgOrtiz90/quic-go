package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"flag"
	"io"
	"bufio"
)

func extractNums(s string) int {
	var n int
	for _, c := range s {
		if '0' <= c && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func minInt(n, m int) int {
	if n < m {
		return n
	}
	return m
}

func main() {

	mergedName := "merged.log"
	mergedOrig := mergedName

	serverDef := "server"
	clientDef := "client"
	cliPrefix := "CLI-->··· "
	srvPrefix := "···<==SRV "

	server := flag.String("server", serverDef, "Server log file (with extension)")
	client := flag.String("client", clientDef, "Client log file (with extension)")
	wpath := flag.String("path", "", "The path of the log files")
	flag.Parse()

	// change working directory
	if *wpath != "" {
		if err := os.Chdir(*wpath); err != nil {
			panic(err)
		}
	}

	// open merged file
	merged, err := os.Create(mergedName)
	defer func() { os.Rename(mergedOrig, mergedName) }()
	if err != nil {
		fmt.Println("Could not open merged.log for writing")
		fmt.Println(err)
		return
	}
	defer merged.Close()

	// Find the last logs
	srvName := *server
	cliName := *client
	var dtst, dtstCli, dtstSrv int
	if *server == serverDef || *client == clientDef {
		err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("Something happened when trying to analyze files: %s\n", err)
			}
			if !strings.Contains(path, ".log") {
				return nil
			}
			dtst = extractNums(path)
			if dtst == 0 {
				return nil
			}
			if *server == serverDef {
				if strings.Contains(strings.ToLower(path), strings.ToLower(*server)) {
					if dtstSrv < dtst {
						srvName = path
						dtstCli = dtst
						return nil
					}
				}
			}
			if *client == clientDef {
				if strings.Contains(strings.ToLower(path), strings.ToLower(*client)) {
					if dtstCli < dtst {
						cliName = path
						dtstCli = dtst
						return nil
					}
				}
			}
			return nil
		})

		// Nothing to merge
		if srvName == *server && cliName == *client {
			return
		}
		if srvName == *server && cliName != *client {
			file, _ := os.Open(cliName)
			io.Copy(merged, file)
			file.Close()
			return
		}
		if srvName != *server && cliName == *client {
			file, _ := os.Open(srvName)
			io.Copy(merged, file)
			file.Close()
			return
		}
	}

	// Prepare new name for merged.log with the earliest datestamp
	mergedName = "merged_"
	dtstSrv = extractNums(srvName)
	dtstCli = extractNums(cliName)
	if dtstCli < dtstSrv {
		dtst = dtstCli
	} else {
		dtst = dtstSrv
	}
	if dtst > 20001231235959 {
		mergedName += "20"
		dtst -= 20000000000000
		//      20001231235959
	}
	var n int
	div := 100000000000
	//   20001231235959
	for {
		n = dtst / div
		mergedName += string('0' + byte(n))
		dtst -= n * div
		if div == 1 {
			break
		}
		div /= 10
		//20001231235959
		if div == 100000 {
			mergedName += "-"
		}
	}
	mergedName += ".log"

	// Open client and server logs
	var srv, cli *os.File
	srv, err = os.Open(srvName)
	if err != nil {
		if _, errr := merged.WriteString(fmt.Sprintf("Could not open server log\n%s\n", err)); errr != nil {
			fmt.Println("Could not open server log")
			fmt.Println(err)
			fmt.Println("Could not write to merged.log neither")
			fmt.Println(errr)
		}
	}
	defer srv.Close()
	cli, err = os.Open(cliName)
	if err != nil {
		if _, errr := merged.WriteString(fmt.Sprintf("Could not open server log\n%s\n", err)); errr != nil {
			fmt.Println("Could not open server log")
			fmt.Println(err)
			fmt.Println("Could not write to merged.log neither")
			fmt.Println(errr)
		}
	}
	defer cli.Close()

	// Merge logs
	dtstLen := len("2006/01/02-15:04:05.000000000")
	cliScanner := bufio.NewScanner(cli)
	srvScanner := bufio.NewScanner(srv)

	srvNotEmpty := srvScanner.Scan()
	cliNotEmpty := cliScanner.Scan()
	txt := srvScanner.Text()
	dtstSrv = extractNums(txt[:minInt(dtstLen, len(txt))])
	txt = cliScanner.Text()
	dtstCli = extractNums(txt[:minInt(dtstLen, len(txt))])
	for srvNotEmpty && cliNotEmpty {
		if dtstSrv <= dtstCli {
			merged.WriteString(srvPrefix + srvScanner.Text() + "\n")
			srvNotEmpty = srvScanner.Scan()
			txt := srvScanner.Text()
			dtstSrv = extractNums(txt[:minInt(dtstLen, len(txt))])
		} else {
			merged.WriteString(cliPrefix + cliScanner.Text() + "\n")
			cliNotEmpty = cliScanner.Scan()
			txt = cliScanner.Text()
			dtstCli = extractNums(txt[:minInt(dtstLen, len(txt))])
		}
	}
	if srvNotEmpty {
		merged.WriteString(srvPrefix + srvScanner.Text() + "\n")
		for srvScanner.Scan() {
			merged.WriteString(srvPrefix + srvScanner.Text() + "\n")
		}
	}
	if cliNotEmpty {
		merged.WriteString(cliPrefix + cliScanner.Text() + "\n")
		for cliScanner.Scan() {
			merged.WriteString(cliPrefix + cliScanner.Text() + "\n")
		}
	}
}
