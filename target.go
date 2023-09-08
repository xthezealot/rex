package main

import (
	"log"
	"net"
	"sync"
)

type Target struct {
	Host  string        `yaml:"-"`
	Ports map[int]*Port `yaml:",omitempty"` // map of port number to port info

	mu sync.Mutex
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
				if _, ok := err.(net.Error); !ok { // err is other than timeout
					log.Printf("error on %s:%d: %v", target.Host, port.Number, err)
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

func (t *Target) HuntSubdomains() {
	defer globalWG.Done()

	if isIP(t.Host) {
		return
	}

	// todo: loop subdomains and `go t.Hunt(wg)`
}
