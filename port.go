package main

import (
	"io"
	"log"
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

var commonPorts = map[int]struct{}{
	21:    {}, // ftp
	22:    {}, // ssh
	23:    {}, // telnet
	80:    {}, // http
	443:   {}, // http
	445:   {}, // smb
	1433:  {}, // mssql
	1521:  {}, // oracle
	2375:  {}, // docker
	3000:  {}, // http
	3306:  {}, // mysql
	5000:  {}, // http
	5432:  {}, // postgresql
	8000:  {}, // http
	8008:  {}, // http
	8080:  {}, // http
	8081:  {}, // http
	8443:  {}, // http
	8888:  {}, // http
	9200:  {}, // elasticsearch
	10250: {}, // kubernetes
	27017: {}, // mongodb
}

var goodStatusCodes = map[int]struct{}{
	200: {},
	201: {},
	202: {},
	204: {},
	205: {},
	206: {},
	304: {},
	401: {},
	402: {},
	403: {},
	405: {},
	406: {},
}

func portInfo(host string, port int) (Port, error) {
	var p Port

	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), time.Second)
	if err != nil {
		return p, err
	}
	defer conn.Close()

	log.Printf("%s:%d open", host, port)

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

			res, err := http.Get(hosturl + filepath.Join("/", path))
			if err != nil {
				break
			}
			defer res.Body.Close()

			finalPath := filepath.Join("/", res.Request.URL.Path)

			// ignore this path if final path (after redirects) is already known on this port
			if _, ok := p.HTTP[finalPath]; ok {
				continue
			}

			// filter status codes
			if res.StatusCode == 429 {
				log.Printf("too many requests (status 429) on %s:%d", host, port)
				break
			}
			if _, ok := goodStatusCodes[res.StatusCode]; !ok {
				continue
			}
			hr.Status = res.StatusCode

			// get content type
			ct, _, _ := mime.ParseMediaType(res.Header.Get("content-type"))
			if ct != "" {
				hr.ContentType = ct
			}
			// todo: reject path if content type not text, html, json, xml or similar

			log.Printf("found %s%s (status %d content type %s)", hosturl, finalPath, hr.Status, hr.ContentType)

			// get server info
			ver := res.Header.Get("server")
			if ver == "" {
				ver = res.Header.Get("x-server")
			}
			if ver != "" {
				p.Version = ver
			}

			// store response
			urlPathForStorage := filepath.Join("/", finalPath)
			if urlPathForStorage == "/" {
				urlPathForStorage = "/index"
			}
			storagePath := filepath.Join(currentDir, "http", host, strconv.Itoa(port), urlPathForStorage)
			storageDirpath := filepath.Dir(storagePath)
			if err = os.MkdirAll(storageDirpath, 0755); err != nil {
				log.Printf("error creating dir %s: %v", storageDirpath, err)
			}

			storageFile, _ := os.Create(storagePath)
			if err != nil {
				log.Printf("error creating file %s: %v", storagePath, err)
			}
			defer storageFile.Close()

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
					log.Printf("error parsing html on %s/%s: %v", host, path, err)
				}
			}

			// todo: nuclei scan with tech detect

			// save response
			p.HTTP[finalPath] = hr
		}

	case 21:
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		lines := strings.SplitN(string(b), "\n", 2)
		line := lines[0]
		if len(line) >= 3 {
			p.Version = strings.TrimSpace(line[3:])
		}

	case 22:
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		b, _ := io.ReadAll(conn)
		re, err := regexp.Compile(`(?im)^.*ssh.*$`)
		if err != nil {
			break
		}
		p.Version = strings.TrimSpace(string(re.Find(b)))

	// todo: 445 (smb): look at smbclient and enum4linux

	// todo: 1433 (mssql): see https://svn.nmap.org/nmap/scripts/ms-sql-ntlm-info.nse

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
