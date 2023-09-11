package main

import (
	"fmt"
	"log"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

type Hunt struct {
	Scope   []string           `yaml:"scope"`
	Targets map[string]*Target `yaml:",omitempty"` // map of host to target info

	mu sync.Mutex
}

func (hunt *Hunt) FromFile(fn string) error {
	b, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, hunt)
}

func (hunt *Hunt) Save() error {
	b, err := yaml.Marshal(hunt)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, b, 0644)
}

// AddTarget tries to add a new target which is not already known.
// If it has been added, it returns true.
func (hunt *Hunt) AddTarget(target *Target) bool {
	hunt.mu.Lock()
	defer hunt.mu.Unlock()

	if _, ok := hunt.Targets[target.Host]; ok {
		return false
	}

	hunt.Targets[target.Host] = target
	return true
}

func (hunt *Hunt) Go() {
	if hunt.Targets == nil {
		hunt.Targets = make(map[string]*Target)
	}

	for _, s := range hunt.Scope {
		hosts := extractHosts(s)
		for _, host := range hosts {
			target := &Target{
				Host: host,
				hunt: hunt,
			}

			if !hunt.AddTarget(target) {
				continue
			}

			log.Printf("new target: %s", target.Host)

			globalWG.Add(1)
			go func() {
				defer globalWG.Done()
				connSemaphore <- struct{}{}
				defer func() { <-connSemaphore }()

				target.Hunt()
			}()

			if *flagSubdomains {
				globalWG.Add(1)
				go func() {
					defer globalWG.Done()

					target.HuntSubdomains()
				}()
			}
		}
	}
}

func (hunt *Hunt) Print() {
	for targetHost, target := range hunt.Targets {
		if len(target.Ports) == 0 {
			continue
		}
		fmt.Printf("%s\n", targetHost)
		for portNumber, port := range target.Ports {
			fmt.Printf("\t:%d  %s  %s\n", portNumber, port.Name, port.Version)
			if len(port.CRLFVuln) > 0 {
				fmt.Printf("\t\t\tCRLF vulns\n")
				for _, url := range port.CRLFVuln {
					fmt.Printf("\033[33m%s\033[0m\n", url)
				}
			}
			for pathstr, path := range port.Paths {
				var status string
				if path.Status <= 299 {
					status = fmt.Sprintf("\033[33m%d\033[0m", path.Status)
				} else {
					status = fmt.Sprintf("\033[31m%d\033[0m", path.Status)
				}
				fmt.Printf("\t\t%s  %s  %s  %s  %s\n", pathstr, status, path.ContentType, path.Tech, path.Title)
			}
		}
	}
}
