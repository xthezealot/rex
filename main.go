package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

const filename = "hunt.yml"

var (
	currentDir string

	connSemaphore chan struct{} // global http semaphore
	globalWG      sync.WaitGroup

	flagSubdomains = flag.Bool("s", false, "hunt for subdomains")
	flagMaxConn    = flag.Int("c", 150, "maximum connections across all targets")
	flagVerbose    = flag.Bool("v", false, "verbose")

	httpclient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
)

func init() {
	if *flagMaxConn < 5 {
		log.Fatalln("maximum connections (flag -c) cannot be under 5")
	}
	connSemaphore = make(chan struct{}, *flagMaxConn)

	var err error
	currentDir, err = os.Getwd()
	if err != nil {
		panic(err)
	}
}

func main() {
	flag.Parse()

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
		hunt.Print()
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
