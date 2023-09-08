package main

import (
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

func (hunt *Hunt) Go() {
	if hunt.Targets == nil {
		hunt.Targets = make(map[string]*Target)
	}

	for _, s := range hunt.Scope {
		hosts := extractHosts(s)
		for _, host := range hosts {
			hunt.mu.Lock()
			if _, ok := hunt.Targets[host]; ok {
				hunt.mu.Unlock()
				continue // do not overwrite old targets
			}
			hunt.mu.Unlock()

			target := &Target{Host: host}
			hunt.mu.Lock()
			hunt.Targets[target.Host] = target
			hunt.mu.Unlock()
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
