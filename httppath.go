package main

import (
	"errors"
	"fmt"
	"math/rand"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/net/html"
)

var (
	errIrrelevantPath  = errors.New("irrelevant path")
	errTooManyRequests = errors.New(http.StatusText(http.StatusTooManyRequests))
)

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

type HTTPPath struct {
	Port *Port  `yaml:"-"`
	Path string `yaml:"-"`

	Status      int      `yaml:",omitempty"`
	ContentType string   `yaml:",omitempty"`
	Title       string   `yaml:",omitempty"`
	Tech        []string `yaml:",omitempty"`
}

func (hp *HTTPPath) Hunt() error {
	url := "http"
	if hp.Port.Number == 443 || hp.Port.Number == 8443 {
		url += "s"
	}
	url += "://" + hp.Port.Target.Host + ":" + strconv.Itoa(hp.Port.Number) + "/" + hp.Path

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))]) // use random user-agent

	// make request (following redirects)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	hp.Status = res.StatusCode
	if hp.Status == http.StatusTooManyRequests {
		return errTooManyRequests
	}
	if hp.Status >= 300 && hp.Status <= 399 ||
		hp.Status == http.StatusNotFound ||
		hp.Status == http.StatusRequestTimeout ||
		hp.Status == http.StatusGone ||
		hp.Status == 460 ||
		hp.Status == 521 ||
		hp.Status == 522 ||
		hp.Status == 523 ||
		hp.Status == 524 ||
		hp.Status == 598 {
		return errIrrelevantPath
	}

	// skip if redirected to another domain
	if res.Request.URL.Hostname() != hp.Port.Target.Host {
		return errIrrelevantPath
	}

	hp.Path = res.Request.URL.Path

	// skip if final path (after redirects) is already known
	hp.Port.mu.Lock()
	if _, ok := hp.Port.Paths[hp.Path]; ok {
		hp.Port.mu.Unlock()
		return errIrrelevantPath
	}
	hp.Port.mu.Unlock()

	// get and filter content type
	hp.ContentType, _, _ = mime.ParseMediaType(res.Header.Get("content-type"))
	if _, ok := interestingContentTypes[hp.ContentType]; hp.ContentType != "" && !ok {
		return errIrrelevantPath
	}

	// get server info
	if tech := res.Header.Get("server"); tech != "" {
		hp.Tech = append(hp.Tech, tech)
	}
	if tech := res.Header.Get("x-server"); tech != "" {
		hp.Tech = append(hp.Tech, tech)
	}

	// if interesting content type, store response
	if _, ok := downloadableContentTypes[hp.ContentType]; ok {
		// create dir
		storagePath := filepath.Join(currentDir, "http", hp.Port.Target.Host, strconv.Itoa(hp.Port.Number), sanitizeFilepath(hp.Path), "index.http")
		storageDirpath := filepath.Dir(storagePath)
		if err = os.MkdirAll(storageDirpath, 0755); err != nil {
			return fmt.Errorf("error creating dir %s: %v", storageDirpath, err)
		}

		// create file
		storageFile, _ := os.Create(storagePath)
		if err != nil {
			return fmt.Errorf("error creating file %s: %v", storagePath, err)
		}
		defer storageFile.Close()

		// save http response to file
		storageFile.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", res.ProtoMajor, res.ProtoMinor, res.StatusCode, res.Status))
		for key, values := range res.Header {
			for _, value := range values {
				storageFile.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
			}
		}
		storageFile.WriteString("\r\n")
		storageFile.ReadFrom(res.Body)

		// if html, get title
		if hp.ContentType == "text/html" {
			storageFile.Seek(0, 0) // reset file reader
			doc, err := html.Parse(storageFile)
			if err == nil {
				var crawler func(*html.Node)
				crawler = func(n *html.Node) {
					if n.Type == html.ElementNode && n.Data == "title" {
						if n.FirstChild != nil {
							hp.Title = n.FirstChild.Data
						}
					}
					for c := n.FirstChild; c != nil; c = c.NextSibling {
						crawler(c)
					}
				}
				crawler(doc)
			} else {
				return fmt.Errorf("error parsing html on %s: %v", url, err)
			}
		}

		// todo: search for secrets in response body

		// todo: if path is /robots.txt, parse file content and add paths to loop

	}

	// todo: nuclei tech-adapted scan

	return nil
}
