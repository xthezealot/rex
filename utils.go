package main

import (
	"encoding/binary"
	"net"
	"net/url"
	"strings"
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
