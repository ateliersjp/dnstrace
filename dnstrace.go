package dnstrace

import (
	"time"

	"github.com/miekg/dns"
	"github.com/ateliersjp/dnstrace/client"
)

const (
	maxRetry = 10 // limit retry of unresolved name to 10 times
)

type Nameserver struct {
	Name       string
	TTL        uint32
}

func Query(qname, qtype string) map[string][]Nameserver {
	qname = dns.Fqdn(qname)
	m := &dns.Msg{}
	if t, ok := dns.StringToType[qtype]; ok {
		m.SetQuestion(qname, t)
	} else {
		m.SetQuestion(qname, dns.TypeA)
	}

	// Set DNSSEC opt to better emulate the default queries from a nameserver.
	o := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	o.SetDo()
	o.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, o)

	c := client.New(maxRetry)
	c.Client.Timeout = 500 * time.Millisecond
	res := map[string][]Nameserver{}
	t := client.Tracer{
		GotIntermediaryResponse: func(i int, m *dns.Msg, rs client.Responses, rtype client.ResponseType) {
			fr := rs.Fastest()
			var r *dns.Msg
			if fr != nil {
				r = fr.Msg
			}

			if rtype == client.ResponseTypeDelegation {
				var label string
				for _, rr := range r.Ns {
					if ns, ok := rr.(*dns.NS); ok {
						label = ns.Header().Name
						break
					}
				}
				_, ns := c.DCache.Get(label)
				res[label] = make([]Nameserver, len(ns))
				for i, s := range ns {
					res[label][i] = Nameserver{
						Name: s.Name,
						TTL:  s.TTL,
					}
				}
			}
		},
	}
	c.RecursiveQuery(m, t)
	return res
}
