package queries

import (
	"github.com/miekg/dns"
	"net"
	prom "zdns/internal/prometheus"
)

func GetAnswer(ipAddress net.IP, hostName string, question dns.Question) dns.RR {
	switch question.Qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   hostName,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: ipAddress,
		}
		prom.SuccessfulResolutionsTotal.Inc()
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    3600, // Например, TTL 1 час
			},
			AAAA: ipAddress, // Пример IPv6-адреса
		}
	default:
		return nil
	}
	return nil
}

func CreateAnswerForAllowedQtype(ipAddress net.IP, hostName string, question *dns.Question) dns.RR {
	switch question.Qtype {
	case dns.TypeA:
		return &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: net.ParseIP(string(ipAddress)),
		}
	case dns.TypeAAAA:
		return &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    3600, // Например, TTL 1 час
			},
			AAAA: net.ParseIP("2001:db8::1"), // Пример IPv6-адреса
		}
	case dns.TypeCNAME:
		return &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600, // Например, TTL 1 час
			},
			Target: "example.com", // Пример целевого доменного имени
		}
	case dns.TypePTR:
		return &dns.PTR{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypePTR,
				Class:  dns.ClassINET,
				Ttl:    3600, // Например, TTL 1 час
			},
			Ptr: "ptr.example.com", // Пример целевого доменного имени
		}
	case dns.TypeSOA:
		return &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600, // Например, TTL 1 час
			},
			Ns:      "ns1.example.com",
			Mbox:    "admin.example.com",
			Serial:  2022010101, // Пример серийного номера
			Refresh: 3600,
			Retry:   600,
			Expire:  604800,
			Minttl:  3600,
		}
	default:
		return nil
	}
}
