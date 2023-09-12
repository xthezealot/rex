package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"runtime"
	"strings"
	"time"

	"golang.org/x/net/html"
)

var userAgents = []string{
	"Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 16_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/115.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
}

// extractHosts returns host addresses (domains or IPs) parsed from s, which can be a domain, an IP, an URL or a CIDR.
func extractHosts(s string) (hosts []string) {
	// Check CIDR
	if _, ipnet, err := net.ParseCIDR(s); err == nil {
		for _, ip := range ipsFromIPNet(ipnet) {
			hosts = append(hosts, ip.String())
		}
		return
	}

	// Extract hostname
	if !strings.Contains(s, "://") {
		s = "http://" + s // fake scheme as needed by url.Parse
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}
	s = u.Hostname()

	// Check IP
	if ip := net.ParseIP(s); ip != nil {
		hosts = append(hosts, ip.String())
		return
	}

	// Check domain
	parts := strings.Split(s, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 || strings.ContainsAny(part, "!\"#$%&'()*+,/;<=>?@[\\]^_`{|}~ ") {
			return
		}
	}
	hosts = append(hosts, s)
	return
}

// Get all IPs from a network without network and broadcast addresses.
func ipsFromIPNet(ipnet *net.IPNet) (ips []net.IP) {
	// convert IPNet struct mask and address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	start := binary.BigEndian.Uint32(ipnet.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip)
	}

	// Remove network and broadcast addresses
	return ips[1 : len(ips)-1]
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}

func sanitizeFilepath(fp string) string {
	fp, err := url.PathUnescape(fp)
	if err != nil {
		return ""
	}

	disallowedChars := []string{"..", "\x00", " ", "*", "?", "[", "]", "`", "$", "\"", "'", ":", "\\", "<", ">", "|"}
	for _, c := range disallowedChars {
		fp = strings.ReplaceAll(fp, c, "_")
	}

	maxLength := 255
	if len(fp) > maxLength {
		fp = fp[:maxLength]
	}

	return fp
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func randUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

func parseTitle(n *html.Node) string {
	if n.Type == html.ElementNode && n.Data == "title" && n.FirstChild != nil {
		return strings.TrimSpace(n.FirstChild.Data)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if title := parseTitle(c); title != "" {
			return title
		}
	}
	return ""
}

func printStats(start time.Time) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	fmt.Println("------")
	fmt.Print("STATS:")
	fmt.Printf("\tTime = %s", time.Since(start))
	fmt.Printf("\tAlloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
	fmt.Println("------")
}
