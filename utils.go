package main

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/url"
	"strings"
)

var httpClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
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
