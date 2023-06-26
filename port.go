package main

import (
	"io"
	"log"
	"math/rand"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	80:    "http",
	443:   "http",
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
	8443:  "http",
	8888:  "http",
	9200:  "elasticsearch",
	10250: "kubernetes",
	27017: "mongodb",
}

var interestingContentTypes = map[string]struct{}{
	"application/gzip":              {},
	"application/javascript":        {},
	"application/json":              {},
	"application/msword":            {},
	"application/octet-stream":      {},
	"application/pdf":               {},
	"application/vnd.ms-excel":      {},
	"application/vnd.ms-powerpoint": {},
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": {},
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         {},
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   {},
	"application/xhtml+xml": {},
	"application/xml":       {},
	"application/zip":       {},
	"text/csv":              {},
	"text/html":             {},
	"text/javascript":       {},
	"text/plain":            {},
	"text/xml":              {},
}

var downloadableContentTypes = map[string]struct{}{
	"application/javascript": {},
	"application/json":       {},
	"application/xhtml+xml":  {},
	"application/xml":        {},
	"text/csv":               {},
	"text/html":              {},
	"text/javascript":        {},
	"text/plain":             {},
	"text/xml":               {},
}

type Port struct {
	Name    string
	Version string                  `yaml:",omitempty"`
	HTTP    map[string]HTTPResponse `yaml:",omitempty"` // map of paths to http response
}

type HTTPResponse struct {
	Status      int    `yaml:",omitempty"`
	ContentType string `yaml:",omitempty"`
	Title       string `yaml:",omitempty"`
}

func portInfo(host string, port int) (Port, error) {
	p := Port{Name: commonPorts[port]}

	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), time.Second)
	if err != nil {
		return p, err
	}
	defer conn.Close()

	log.Printf("port %d is open on %s", port, host)

	// get port info with method adapted to port number
	switch port {

	// common http ports
	case 80, 443, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888:
		p.HTTP = make(map[string]HTTPResponse)

		hosturl := "http"
		if port == 443 {
			hosturl += "s"
		}
		hosturl += "://" + host + ":" + strconv.Itoa(port)

		// bruteforce paths
		for path := range pathsWordlist {
			var hr HTTPResponse

			// prepare request with exact word from list and random user-agent
			req, err := http.NewRequest("GET", hosturl+"/"+path, nil)
			if err != nil {
				log.Printf("get request creation for %s: %v", hosturl+"/"+path, err)
				break
			}
			req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])

			// make request (following redirects)
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("get request to %s: %v", req.URL.String(), err)
				break
			}
			defer res.Body.Close()

			// get and filter status codes
			hr.Status = res.StatusCode
			if hr.Status == 429 {
				log.Printf("too many requests (status 429) on %s", res.Request.URL.Host)
				break
			}
			if hr.Status >= 300 && hr.Status <= 399 || hr.Status == 404 {
				continue
			}

			// skip if redirected to another domain
			if res.Request.URL.Hostname() != host {
				continue
			}

			finalPath := res.Request.URL.Path

			// skip if final path (after redirects) is already in p.HTTP
			if _, ok := p.HTTP[finalPath]; ok {
				continue
			}

			// get and filter content type
			hr.ContentType, _, _ = mime.ParseMediaType(res.Header.Get("content-type"))
			if _, ok := interestingContentTypes[hr.ContentType]; hr.ContentType != "" && !ok {
				continue
			}

			log.Printf("found %s (%d, %q)", res.Request.URL.String(), hr.Status, hr.ContentType)

			// get server version info
			ver := res.Header.Get("server")
			if ver == "" {
				ver = res.Header.Get("x-server")
			}
			if len(ver) > len(p.Version) { // keep the most specific (longest) vesion info
				p.Version = ver
			}

			// if interesting content type, store response
			if _, ok := downloadableContentTypes[hr.ContentType]; ok {
				// use final path and be careful to replace ".." in path
				storageURLPath := strings.ReplaceAll(finalPath, "..", "PARENT")
				if storageURLPath == "/" {
					storageURLPath = "/INDEX"
				}

				// create dir
				storagePath := filepath.Join(currentDir, "http", host, strconv.Itoa(port), storageURLPath)
				storageDirpath := filepath.Dir(storagePath)
				if err = os.MkdirAll(storageDirpath, 0755); err != nil {
					log.Printf("error creating dir %s: %v", storageDirpath, err)
				}

				// create file
				storageFile, _ := os.Create(storagePath)
				if err != nil {
					log.Printf("error creating file %s: %v", storagePath, err)
				}
				defer storageFile.Close()

				// save file
				if _, err = io.Copy(storageFile, res.Body); err != nil {
					log.Printf("error writing body to file %s: %v", storagePath, err)
				}

				// if html, get title
				if hr.ContentType == "text/html" {
					storageFile.Seek(0, 0) // reset file reader
					doc, err := html.Parse(storageFile)
					if err == nil {
						var crawler func(*html.Node)
						crawler = func(n *html.Node) {
							if n.Type == html.ElementNode && n.Data == "title" {
								if n.FirstChild != nil {
									hr.Title = n.FirstChild.Data
								}
							}
							for c := n.FirstChild; c != nil; c = c.NextSibling {
								crawler(c)
							}
						}
						crawler(doc)
					} else {
						log.Printf("error parsing html on %s%s: %v", host, path, err)
					}
				}

				// todo: if path is /robots.txt, parse file content and add paths to loop

				// todo: read file and try to find secrets
			}

			// todo: nuclei tech-adapted scan

			// save response
			p.HTTP[finalPath] = hr
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
			break
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
			break
		}
		p.Version = strings.TrimSpace(string(re.Find(b)))

	}

	return p, err
}
