package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const filename = "hunt.yml"

var (
	currentDir string

	connSemaphore chan struct{} // global http semaphore
	globalWG      sync.WaitGroup

	flagSubdomains = flag.Bool("d", false, "hunt for subdomains")
	flagScan       = flag.Bool("s", false, "run vuln scanners during hunt")
	flagMaxConn    = flag.Int("c", 150, "maximum parallel connections across all targets")
	flagVerbose    = flag.Bool("v", false, "verbose")

	wappalyzerClient *wappalyzer.Wappalyze

	httpclient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

func main() {
	flag.Parse()
	if *flagMaxConn < 5 {
		log.Fatalln("maximum connections (flag -c) cannot be under 5")
	}

	connSemaphore = make(chan struct{}, *flagMaxConn)

	var err error

	if currentDir, err = os.Getwd(); err != nil {
		panic(err)
	}

	if wappalyzerClient, err = wappalyzer.New(); err != nil {
		panic(err)
	}

	hunt := new(Hunt)

	if err := hunt.FromFile(filename); err != nil {
		if os.IsNotExist(err) {
			hunt.Scope = []string{""}
			hunt.Save()
			log.Printf("add scope to %s", filename)
			os.Exit(0)
		}
		panic(err)
	}

	// only print current hunt if requested
	if flag.Arg(0) == "p" {
		pCmd := flag.NewFlagSet("p", flag.ExitOnError)
		allFlag := pCmd.Bool("a", false, "show all paths (even errors)")
		pCmd.Parse(os.Args[2:])

		hunt.Print(*allFlag)
		os.Exit(0)
	}

	// always save hunt at the end
	defer func() {
		if err := hunt.Save(); err != nil {
			panic(err)
		}
		log.Printf("hunt saved in %s", filename)
	}()

	start := time.Now()

	hunt.Go()
	globalWG.Wait()

	if *flagVerbose {
		printStats(start)
	}
}
