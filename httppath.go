package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

	body []byte
}

func (hp *HTTPPath) StoragePath() string {
	path := filepath.Clean(hp.Path) // remove ".." path traversal
	return filepath.Join(currentDir, "http", hp.Port.Target.Host, strconv.Itoa(hp.Port.Number), path, "index.http")
}

func (hp *HTTPPath) URL() string {
	if !strings.HasPrefix(hp.Path, "/") {
		hp.Path = "/" + hp.Path
	}

	return hp.Port.URL() + hp.Path
}

func (hp *HTTPPath) AddTech(s string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return
	}
	s = strings.ToLower(s)
	for _, tech := range hp.Tech {
		if tech == s {
			return
		}
	}
	hp.Tech = append(hp.Tech, s)
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

	// keep final path (after redirections) and urlencode for storage
	hp.Path = encodePath(res.Request.URL.Path)

	// ignore path if already known
	if _, ok := hp.Port.Paths[hp.Path]; ok {
		return errIrrelevantPath
	}

	// get and filter content type
	hp.ContentType, _, _ = mime.ParseMediaType(res.Header.Get("content-type"))
	if _, ok := interestingContentTypes[hp.ContentType]; hp.ContentType != "" && !ok {
		return errIrrelevantPath
	}

	// ok until there, keep body in memory
	if hp.body, err = io.ReadAll(res.Body); err != nil {
		return err
	}

	// get title if html
	if err = hp.ParseTitle(); *flagVerbose && err != nil {
		log.Printf("error parsing title on %s: %v", hp.URL(), err)
	}

	// ditch waf pages based on title
	titleLower := strings.ToLower(hp.Title)
	if strings.Contains(titleLower, "cloudflare") ||
		strings.Contains(titleLower, "verify") && strings.Contains(titleLower, "human") {
		return errIrrelevantPath
	}

	// get server info
	hp.AddTech(res.Header.Get("server"))
	hp.AddTech(res.Header.Get("x-server"))

	// wappalyze tech
	if err = hp.Wappalyze(res); *flagVerbose && err != nil {
		log.Printf("error wappalyzing %s: %v", hp.URL(), err)
	}

	// if interesting content type, store response
	if err = hp.Save(res); *flagVerbose && err != nil {
		log.Printf("error saving request on disk for %s: %v", hp.URL(), err)
	}

	// todo: if path is /robots.txt, parse file content and add paths to loop

	// todo: try 40x bypass (see github.com/lobuhi/byp4xx)

	// run scanners if status is promising
	if *flagScan && hp.Status <= 299 {
		if err = hp.ScanXSS(); *flagVerbose && err != nil {
			log.Printf("error on xss check for  %s: %v", hp.URL(), err)
		}

		// todo: scan for secrets (see github.com/securing/dumpsterdiver)
		// todo: scan for cors (see github.com/s0md3v/corsy)
		// todo: scan for open redirection (see github.com/r0075h3ll/oralyzer)
		// todo: scan for prototype pollution (see github.com/dwisiswant0/ppfuzz)
		// todo: scan for sqli
		// todo: scan for ssrf
		// todo: scan for ssti according to detected tech
		// todo: scan for secrets in response body
		// todo: scan for cache poisoning (see github.com/hackmanit/web-cache-vulnerability-scanner)
		// todo: cms-adapted scan (see github.com/tuhinshubhra/cmseek)
		// todo: nuclei tech-adapted scan
	}

	return nil
}

func (hp *HTTPPath) Save(res *http.Response) (err error) {
	if _, ok := downloadableContentTypes[hp.ContentType]; !ok {
		return nil // don't show an error because of content type
	}

	// create dir
	if err = os.MkdirAll(filepath.Dir(hp.StoragePath()), 0755); err != nil {
		return
	}

	// create file
	var f *os.File
	if f, err = os.Create(hp.StoragePath()); err != nil {
		return
	}
	defer f.Close()

	// save http response to file
	f.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n", res.ProtoMajor, res.ProtoMinor, res.StatusCode, res.Status))
	for key, values := range res.Header {
		for _, value := range values {
			if _, err = f.WriteString(fmt.Sprintf("%s: %s\r\n", key, value)); err != nil {
				return
			}
		}
	}
	if _, err = f.WriteString("\r\n"); err != nil {
		return
	}
	_, err = f.Write(hp.body)
	return
}

func (hp *HTTPPath) ParseTitle() error {
	if hp.ContentType != "text/html" {
		return nil // don't show an error because of content type
	}

	doc, err := html.Parse(bytes.NewReader(hp.body))
	if err != nil {
		return err
	}

	hp.Title = parseTitle(doc)
	return nil
}

func (hp *HTTPPath) Wappalyze(res *http.Response) error {
	if hp.ContentType != "text/html" {
		return nil
	}

	for fingerprint := range wappalyzerClient.Fingerprint(res.Header, hp.body) {
		hp.AddTech(fingerprint)
	}

	return nil
}

// todo: custom xss scan
func (hp *HTTPPath) ScanXSS() error {
	if hp.ContentType != "text/html" {
		return nil
	}

	xss, err := dalfox.NewScan(dalfox.Target{
		Method: "GET",
		URL:    hp.URL(),
		Options: dalfox.Options{
			UserAgent: randUserAgent(),
		},
	})

	if err != nil {
		return err
	}
	if !xss.IsFound() {
		return nil
	}

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
	return nil
}
