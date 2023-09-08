package main

import (
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	80:    "http",
	443:   "https",
	445:   "smb",
	1433:  "mssql",
	1521:  "oracle",
	2375:  "docker",
	3000:  "http",
	3306:  "mysql",
	5000:  "http",
	5432:  "postgresql",
	8000:  "http",
	8008:  "http",
	8080:  "http",
	8081:  "http",
	8443:  "https",
	8888:  "http",
	9200:  "elasticsearch",
	10250: "kubernetes",
	27017: "mongodb",
}

type Port struct {
	Target  *Target `yaml:"-"`
	Number  int     `yaml:"-"`
	Name    string
	Version string               `yaml:",omitempty"`
	Paths   map[string]*HTTPPath `yaml:",omitempty"` // map of paths to http response

	mu sync.Mutex
}

func (p *Port) Hunt() error {
	conn, err := net.DialTimeout("tcp", p.Target.Host+":"+strconv.Itoa(p.Number), 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	// get port info with method adapted to port number
	switch p.Number {

	// common http ports
	case 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888:
		p.Paths = make(map[string]*HTTPPath)

		// bruteforce paths
		for path := range pathsWordlist {
			hp := &HTTPPath{
				Port: p,
				Path: path,
			}

			globalWG.Add(1)
			go func() {
				defer globalWG.Done()
				connSemaphore <- struct{}{}
				defer func() { <-connSemaphore }()

				if err := hp.Hunt(); err != nil {
					if err != errIrrelevantPath {
						log.Printf("error on %s:%d/%s: %v", p.Target.Host, p.Number, hp.Path, err)
					}
					return
				}

				p.mu.Lock()
				p.Paths[hp.Path] = hp
				p.mu.Unlock()

				log.Printf("found %s:%d%s (%d, %q)", p.Target.Host, p.Number, hp.Path, hp.Status, hp.ContentType)
			}()
		}

	// ftp
	case 21:
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		lines := strings.SplitN(string(b), "\n", 2)
		line := lines[0]
		if len(line) >= 3 {
			p.Version = strings.TrimSpace(line[3:])
		}

	// ssh
	case 22:
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		re, err := regexp.Compile(`(?im)^.*ssh.*$`)
		if err != nil {
			return err
		}
		p.Version = strings.TrimSpace(string(re.Find(b)))

	// todo: 445 (smb): see smbclient and enum4linux

	// todo: 1433 (mssql): see https://svn.nmap.org/nmap/scripts/ms-sql-ntlm-info.nse

	// mysql
	case 3306:
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		re, err := regexp.Compile(`(?m)^[0-9a-zA-Z-_+.]{3,}`)
		if err != nil {
			return err
		}
		p.Version = strings.TrimSpace(string(re.Find(b)))

	}

	return nil
}
