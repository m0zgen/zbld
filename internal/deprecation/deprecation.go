package deprecation

import (
	"github.com/miekg/dns"
	"net"
)

// processTXT - Process TXT records and add them to the answer
func processTXT(answerRR []dns.RR, m *dns.Msg) {
	for _, rr := range answerRR {
		if txt, ok := rr.(*dns.TXT); ok {
			// Extract needed data from TXT record
			// As example: txt.Txt
			// Then add this data to the answer
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    txt.Hdr.Ttl},
				Txt: txt.Txt,
				// Another TXT fields
			})
		}
	}
}

// proccessA - Process A records and add them to the answer
func processA(answerRR []dns.RR, m *dns.Msg) {
	for _, rr := range answerRR {
		if a, ok := rr.(*dns.A); ok {

			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    a.Hdr.Ttl},
				A: a.A,
			})
		}
	}
}

// GetAv4 - Get A record from IPv4 upstream
func GetAv4(ipAddress net.IP, hostName string, question dns.Question) dns.RR {
	switch question.Qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: ipAddress,
		}
	default:
		return nil
	}
}

// GetAAAAv6 - Get AAAA record from IPv6 upstream
func GetAAAAv6(ipAddress net.IP, hostName string, question dns.Question) dns.RR {
	switch question.Qtype {
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			AAAA: ipAddress,
		}
	default:
		return nil
	}
}
