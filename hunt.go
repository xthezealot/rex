package main

import (
	"fmt"
	"log"
	"os"
	"strings"
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

func (hunt *Hunt) Print(showAll bool) {
	for targetHost, target := range hunt.Targets {
		if len(target.Ports) == 0 {
			continue
		}
		fmt.Printf("\033[1m%s\033[0m\n", targetHost)
		for portNumber, port := range target.Ports {

			fmt.Printf("\t\033[1m:%d\033[0m  \033[2m%s\033[0m", portNumber, port.Name)

			if port.Version != "" {
				fmt.Printf("  \033[35m%s\033[0m", port.Version)
			}

			fmt.Print("\n")

			if len(port.CRLFVuln) > 0 {
				fmt.Printf("\t\t\033[5;27;41m CRLF vulns \033[0m\n")
				for _, url := range port.CRLFVuln {
					fmt.Printf("\t\t\t\033[31m%s\033[0m\n", url)
				}
			}

			for pathstr, path := range port.Paths {
				if !showAll && path.Status >= 300 {
					continue
				}

				var status string

				if path.Status <= 299 {
					status = fmt.Sprintf("\033[32m%d\033[0m", path.Status)
				} else {
					status = fmt.Sprintf("\033[31m%d\033[0m", path.Status)
				}

				fmt.Printf("\t\t\033[1m%s\033[0m  %s", pathstr, status)

				if path.ContentType == "text/html" {
					fmt.Printf("  \033[33m%s\033[0m", path.ContentType)
				} else if path.ContentType != "" {
					fmt.Printf("  \033[93m%s\033[0m", path.ContentType)
				}

				if len(path.Tech) > 0 {
					fmt.Printf("  \033[35m%s\033[0m", strings.Join(path.Tech, ", "))
				}

				if path.Title != "" {
					fmt.Printf("  \033[34m%s\033[0m", path.Title)
				}

				fmt.Print("\n")

				if len(path.XSS) > 0 {
					fmt.Printf("\t\t\t\033[5;27;41m XSS vulns \033[0m\n")
					for _, poc := range path.XSS {
						fmt.Printf("\t\t\t\t?\033[31m%s\033[0m=%s\n", poc.Param, poc.Payload)
					}
				}
			}
		}
	}
}
