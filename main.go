package main

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

const filename = "hunt.yml"

var currentDir string

type Hunt struct {
	Scope   []string          `yaml:"scope"`
	Targets map[string]Target `yaml:",omitempty"` // map of host to target info
	mu      sync.Mutex
}

type Target struct {
	Ports map[int]Port `yaml:",omitempty"` // map of port number to port info
}

func init() {
	var err error
	currentDir, err = os.Getwd()
	if err != nil {
		panic(err)
	}

	// get wordlist in memory
	// f, err := os.Open("wordlist.txt")
	// if err != nil {
	// 	panic(err)
	// }
	// sc := bufio.NewScanner(f)
	// for sc.Scan() {
	// 	pathsWordlist[sc.Text()] = struct{}{}
	// }
	// if err := sc.Err(); err != nil {
	// 	log.Fatal(err)
	// }
}

func main() {
	// fmt.Println(portInfo("alefunion.com", 80))
	// os.Exit(0)

	hunt := &Hunt{}

	b, err := os.ReadFile(filename)
	if err != nil {
		// make a new file if it not exists
		if os.IsNotExist(err) {
			f, err := os.Create(filename)
			if err != nil {
				panic(err)
			}

			hunt.Scope = []string{""}
			b, err := yaml.Marshal(hunt)
			if err != nil {
				panic(err)
			}

			if _, err = f.Write(b); err != nil {
				panic(err)
			}
			log.Printf("file %s created", filename)
			os.Exit(0)
		}
		panic(err)
	}

	// retreive hunt from file
	if err = yaml.Unmarshal(b, &hunt); err != nil {
		panic(err)
	}

	// init values
	if hunt.Targets == nil {
		hunt.Targets = make(map[string]Target)
	}

	var domainsToSubfind []string

	// add new targets from scope
	for _, s := range hunt.Scope {
		hh := extractHosts(s)
		for _, h := range hh {
			// do not overwrite old targets
			if _, ok := hunt.Targets[h]; ok {
				continue
			}
			// if new domain, add to domains to subfind
			if !isIP(h) {
				domainsToSubfind = append(domainsToSubfind, h)
			}
			// add to targets
			hunt.Targets[h] = Target{}
			log.Printf("new target: %s", h)
		}
	}

	// find subdomains
	if len(domainsToSubfind) > 0 {
		log.Println("subdomain search started")
		cmd := exec.Command("subfinder", "-all", "-active", "-silent")
		cmd.Stdin = strings.NewReader(strings.Join(domainsToSubfind, "\n"))
		if b, err = cmd.Output(); err != nil {
			panic(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			s := sc.Text()
			hh := extractHosts(s)
			for _, h := range hh {
				// do not overwrite old targets
				if _, ok := hunt.Targets[h]; ok {
					continue
				}
				// add to targets
				hunt.Targets[h] = Target{}
				log.Printf("new target: %s", h)
			}
		}
	}

	// todo: save hunt

	// scan targets
	var wg sync.WaitGroup
	for host, target := range hunt.Targets {
		// do not overwrite old target
		if len(target.Ports) > 0 {
			continue
		}

		wg.Add(1)
		sem := make(chan struct{}, 150) // semaphore with n slots
		go func(host string, target Target) {
			defer wg.Done()
			sem <- struct{}{}        // acquire semaphore
			defer func() { <-sem }() // release semaphore

			// check host exists
			if _, err := net.LookupHost(host); err != nil {
				return
			}

			// scan common ports
			target.Ports = make(map[int]Port)
			for port := range commonPorts {
				p, err := portInfo(host, port)
				if err != nil {
					continue
				}
				target.Ports[port] = p
			}

			// todo: nuclei generic scan

			// save target
			hunt.mu.Lock()
			defer hunt.mu.Unlock()
			hunt.Targets[host] = target
		}(host, target)
	}
	wg.Wait()

	// save hunt
	if b, err = yaml.Marshal(hunt); err != nil {
		panic(err)
	}
	if err = os.WriteFile(filename, b, 0644); err != nil {
		panic(err)
	}
	log.Printf("hunt saved in %s", filename)
}
