package main

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os/exec"
	"sync"
)

type Target struct {
	Host  string        `yaml:"-"`
	Ports map[int]*Port `yaml:",omitempty"` // map of port number to port info

	hunt *Hunt
	mu   sync.Mutex
}

func (target *Target) Hunt() {
	target.Ports = make(map[int]*Port)

	for portNum, portName := range commonPorts {
		port := &Port{
			Target: target,
			Number: portNum,
			Name:   portName,
		}

		// if not an ip, check that host can be resolved before pursuing
		if !isIP(target.Host) {
			if _, err := net.LookupHost(target.Host); err != nil {
				if *flagVerbose {
					log.Printf("%s cannot be resolved", target.Host)
				}
				return
			}
		}

		globalWG.Add(1)
		go func() {
			defer globalWG.Done()
			connSemaphore <- struct{}{}
			defer func() { <-connSemaphore }()

			if err := port.Hunt(); err != nil {
				if *flagVerbose {
					if _, ok := err.(net.Error); !ok { // err is other than timeout
						log.Printf("error on %s:%d: %v", target.Host, port.Number, err)
					}
				}
				return
			}

			target.mu.Lock()
			target.Ports[port.Number] = port
			target.mu.Unlock()

			log.Printf("found %s:%d", target.Host, port.Number)
		}()
	}

	// todo: nuclei generic scan
	// todo: google dorks search (see github.com/six2dez/dorks_hunter)
	// todo: github dorks search (see github.com/obheda12/gitdorker & github.com/damit5/gitdorks_go)
	// todo: github leaks (see github.com/gitleaks/gitleaks & github.com/trufflesecurity/trufflehog)
}

func (target *Target) HuntSubdomains() {
	if isIP(target.Host) {
		return
	}

	cmd := exec.Command("subfinder", "-all", "-silent", "-d", target.Host)
	b, err := cmd.Output()
	if err != nil {
		panic(err)
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		s := sc.Text()
		hosts := extractHosts(s)
		for _, host := range hosts {
			subtarget := &Target{
				Host: host,
				hunt: target.hunt,
			}

			if !target.hunt.AddTarget(subtarget) {
				continue
			}

			// check that host can be resolved before pursuing
			if _, err := net.LookupHost(target.Host); err != nil {
				if *flagVerbose {
					log.Printf("found %s but cannot be resolved", subtarget.Host)
				}
				return
			}

			log.Printf("new target: %s", subtarget.Host)

			globalWG.Add(1)
			go func() {
				defer globalWG.Done()
				connSemaphore <- struct{}{}
				defer func() { <-connSemaphore }()

				subtarget.Hunt()
			}()
		}
	}

	// todo: brutefoce subdomains from wordlist (and check that host can be resolved before pursuing)
}
