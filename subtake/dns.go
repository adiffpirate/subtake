package subtake

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

func (s *Subdomain) dns(o *Options) {
	config := fingerprints(o.Config)
	detect(s.Url, o.Output, o.Ssl, o.Verbose, o.Timeout, config)
}

func resolve(url string) (cname string) {
	cname = ""
	d := new(dns.Msg)
	d.SetQuestion(url+".", dns.TypeCNAME)
	ret, err := dns.Exchange(d, "1.1.1.1:53")
	if err != nil {
		return
	}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.CNAME); ok {
			cname = t.Target
		}
	}

	return cname
}

func nslookup(domain string) (nameservers []string) {
	m := new(dns.Msg)
	m.SetQuestion(dotDomain(domain), dns.TypeNS)
	ret, err := dns.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return
	}

	nameservers = []string{}

	for _, a := range ret.Answer {
		if t, ok := a.(*dns.NS); ok {
			nameservers = append(nameservers, t.Ns)
		}
	}

	return nameservers
}

func nxdomain(nameserver string) bool {
	if _, err := net.LookupHost(nameserver); err != nil {
		if strings.Contains(fmt.Sprintln(err), "no such host") {
			return true
		}
	}

	return false
}

