package main

import (
	"bufio"
	"bytes"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const filename = "hunt.yml"

var commonPorts = map[int]string{
	80:   "http",
	443:  "http",
	3000: "http",
	5000: "http",
	8000: "http",
	8008: "http",
	8080: "http",
	8081: "http",
	8443: "http",
	8888: "http",

	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	2375:  "docker",
	3306:  "mysql",
	5432:  "postgresql",
	9200:  "elasticsearch",
	10250: "kubernetes",
	27017: "mongodb",
}

type Hunt struct {
	Scope   []string          `yaml:"scope"`
	Targets map[string]Target `yaml:",omitempty"`
	mu      sync.Mutex
}

type Target struct {
	Ports map[int]Port `yaml:",omitempty"`
}

type Port struct {
	Version string
	HTTP    HTTP `yaml:",omitempty"`
}

type HTTP struct {
	ContentType string
	Title       string
}

func main() {
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
		log.Println("started subdomains search")
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

	// scan targets
	var wg sync.WaitGroup
	for host, target := range hunt.Targets {
		// do not overwrite old ports
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
			for cp, name := range commonPorts {
				t := time.Now()
				conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(cp), time.Second)
				log.Printf("checked port %d (%s) on %s in %dms", cp, name, host, time.Since(t).Milliseconds())
				if err != nil {
					continue
				}
				conn.Close()

				// todo: http/html request when needed

				log.Printf("port %d (%s) is open on %s", cp, name, host)

				// save port
				target.Ports[cp] = Port{
					Version: name,
				}
			}

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
