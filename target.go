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
}
