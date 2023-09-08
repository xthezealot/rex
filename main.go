package main

import (
	"flag"
	"log"
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
)

func init() {
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
			os.Exit(0)
		}
		panic(err)
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
