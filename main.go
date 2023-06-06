package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
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

var pathsWordlist = map[string]struct{}{
	"":        {},
	".env":    {},
	"contact": {},
}

type Hunt struct {
	Scope   []string          `yaml:"scope"`
	Targets map[string]Target `yaml:",omitempty"` // map of host to target info
	mu      sync.Mutex
}

type Target struct {
	Ports map[int]Port `yaml:",omitempty"` // map of port number to port info
}

type Port struct {
	Version string
	HTTP    map[string]HTTPResponse `yaml:",omitempty"` // map of paths to http response
}

type HTTPResponse struct {
	ContentType string
	Title       string
}

func main() {
	fmt.Println(portInfo("62.210.115.117", 21))
	os.Exit(0)

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
			for port, name := range commonPorts {
				p, err := portInfo(host, port)
				if err != nil {
					continue
				}
				target.Ports[port] = p
				log.Printf("port %d (%s) is open on %s", port, name, host)
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

func portInfo(host string, port int) (Port, error) {
	p := Port{
		Version: commonPorts[port],
	}

	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), time.Second)
	if err != nil {
		return p, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(conn)

	// parse service version
	var ver string
	switch port {

	// common http ports
	case 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888:
		p.HTTP = make(map[string]HTTPResponse)

		scheme := "http"
		if port == 443 {
			scheme += "s"
		}

		// bruteforce paths
		for path, _ := range pathsWordlist {
			// todo: make http response

			res, err := http.Get(scheme + "://" + host + ":" + strconv.Itoa(port) + "/" + path)
			if err != nil {
				break
			}
			defer res.Body.Close()

			doc, err := html.Parse(res.Body)
			if err != nil {
				break
			}
			var crawler func(*html.Node)
			crawler = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "title" {
					if n.FirstChild != nil {
						p.HTTP.Title = n.FirstChild.Data // todo
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					crawler(c)
				}
			}
			crawler(doc)

			// todo: save response if final path (after redirects) is not known
		}

	case 21:
		lines := strings.SplitN(string(b), "\n", 2)
		line := lines[0]
		if len(line) >= 3 {
			ver = strings.TrimSpace(line[3:])
		}

	case 22:
		re, err := regexp.Compile(`(?im)^.*ssh.*$`)
		if err != nil {
			break
		}
		ver = strings.TrimSpace(string(re.Find(b)))

	// todo: 445 (smb): look at smbclient and enum4linux

	// todo: 1433 (mssql): see https://svn.nmap.org/nmap/scripts/ms-sql-ntlm-info.nse

	case 3306:
		re, err := regexp.Compile(`(?m)^[0-9a-zA-Z-_+.]{3,}`)
		if err != nil {
			break
		}
		ver = strings.TrimSpace(string(re.Find(b)))

	}

	if ver != "" {
		p.Version += " (" + ver + ")"
	}

	return p, err
}
