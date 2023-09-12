package main

import (
	"errors"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	dalfox "github.com/hahwul/dalfox/v2/lib"
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

type XSSPoC struct {
	Data     string `yaml:",omitempty"`
	Param    string `yaml:",omitempty"`
	Payload  string `yaml:",omitempty"`
	Evidence string `yaml:",omitempty"`
	CWE      string `yaml:",omitempty"`
	Severity string `yaml:",omitempty"`
}

type HTTPPath struct {
	Port *Port  `yaml:"-"`
	Path string `yaml:"-"`

	Status      int       `yaml:",omitempty"`
	ContentType string    `yaml:"contentType,omitempty"`
	Title       string    `yaml:",omitempty"`
	Tech        []string  `yaml:",omitempty"`
	XSS         []*XSSPoC `yaml:",omitempty"`

	storageFile *os.File
}

func (hp *HTTPPath) StoragePath() string {
	return filepath.Join(currentDir, "http", hp.Port.Target.Host, strconv.Itoa(hp.Port.Number), sanitizeFilepath(hp.Path), "index.http")
}

func (hp *HTTPPath) URL() string {
	return hp.Port.URL() + "/" + hp.Path
}

func (hp *HTTPPath) Save(res *http.Response) (err error) {
	if _, ok := downloadableContentTypes[hp.ContentType]; !ok {
		return fmt.Errorf("content type %q is not interesting for download", hp.ContentType)
	}

	storagePath := hp.StoragePath()

	// create dir
	storageDirpath := filepath.Dir(storagePath)
	if err = os.MkdirAll(storageDirpath, 0755); err != nil {
		return
	}

	// create file
	if hp.storageFile, err = os.Create(storagePath); err != nil {
		return
	}
	defer hp.storageFile.Close()

	// save http response to file
	hp.storageFile.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", res.ProtoMajor, res.ProtoMinor, res.StatusCode, res.Status))
	for key, values := range res.Header {
		for _, value := range values {
			if _, err = hp.storageFile.WriteString(fmt.Sprintf("%s: %s\r\n", key, value)); err != nil {
				return
			}
		}
	}
	if _, err = hp.storageFile.WriteString("\r\n"); err != nil {
		return
	}
	_, err = hp.storageFile.ReadFrom(res.Body)
	return
}

func (hp *HTTPPath) ParseTitle() error {
	if hp.ContentType != "text/html" {
		return nil // don't show an error because of content type
	}

	f, err := os.Open(hp.StoragePath())
	if err != nil {
		return err
	}
	defer f.Close()

	doc, err := html.Parse(f)
	if err != nil {
		return err
	}

	hp.Title = parseTitle(doc)
	return nil
}

func (hp *HTTPPath) Hunt() error {
	req, err := http.NewRequest("GET", hp.URL(), nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", randUserAgent()) // use random user-agent

	// make request (following redirects)
	res, err := httpclient.Do(req)
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
	if err = hp.Save(res); *flagVerbose && err != nil {
		log.Printf("error saving request on disk for %s: %v", hp.URL(), err)
	}

	// get title if html
	if err = hp.ParseTitle(); *flagVerbose && err != nil {
		log.Printf("error parsing title on %s: %v", hp.URL(), err)
	}

	// ditch waf pages
	if strings.Contains(hp.Title, "Cloudflare") {
		return errIrrelevantPath
	}

	// xss scan
	xss, err := dalfox.NewScan(dalfox.Target{
		Method: "GET",
		URL:    hp.URL(),
		Options: dalfox.Options{
			UserAgent: randUserAgent(),
		},
	})
	if err != nil {
		if *flagVerbose {
			log.Printf("error on xss check for  %s: %v", hp.URL(), err)
		}
	} else if xss.IsFound() {
		for _, poc := range xss.PoCs {
			hp.XSS = append(hp.XSS, &XSSPoC{
				Data:     poc.Data,
				Param:    poc.Param,
				Payload:  poc.Payload,
				Evidence: poc.Evidence,
				CWE:      poc.CWE,
				Severity: poc.Severity,
			})
		}
		log.Printf("xss vuln on %s", hp.URL())
	}

	// todo: search for secrets in response body

	// todo: if path is /robots.txt, parse file content and add paths to loop

	// todo: nuclei tech-adapted scan

	return nil
}
