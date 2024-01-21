package queries

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
	"zdns/internal/cache"
)

// Local functions ---------------------------------------------------------- //

// processSOA - Process SOA records and add them to the answer
func processSOA(answerRR []dns.RR, m *dns.Msg) {
	for _, rr := range answerRR {
		if soa, ok := rr.(*dns.SOA); ok {
			// Extract needed data from SOA record
			// As example: soa.Ns, soa.Mbox, soa.Serial etc.
			// Then add this data to the answer
			m.Answer = append(m.Answer, &dns.SOA{
				Hdr: dns.RR_Header{
					Name:   m.Question[0].Name,
					Rrtype: dns.TypeSOA,
					Class:  dns.ClassINET,
					Ttl:    soa.Hdr.Ttl},
				Ns:      soa.Ns,
				Mbox:    soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Refresh,
				Expire:  soa.Expire,
				Minttl:  soa.Minttl,
				// Another SOA fields
			})
		}
	}
}

// hasSOARecords - Check if the response has SOA records
func hasSOARecords(response *dns.Msg) bool {
	// Check Answer section
	if len(response.Answer) > 0 {
		for _, rr := range response.Answer {
			if _, ok := rr.(*dns.SOA); ok {
				return true
			}
		}
	}

	// Check Authority section
	if len(response.Ns) > 0 {
		for _, rr := range response.Ns {
			if _, ok := rr.(*dns.SOA); ok {
				return true
			}
		}
	}

	// Check Additional section
	if len(response.Extra) > 0 {
		for _, rr := range response.Extra {
			if _, ok := rr.(*dns.SOA); ok {
				return true
			}
		}
	}

	return false
}

// External functions ------------------------------------------------------- //

// bindAnswerCache - Bind DNS mdg answer to the cache
func bindAnswerCache(resp *dns.Msg, hostName string, question dns.Question) {

	// Create cache entry
	entry := cache.CacheEntry{
		IPv4:         []net.IP{},
		IPv6:         []net.IP{},
		CreationTime: time.Now(),
		TTL:          time.Duration(resp.Answer[0].Header().Ttl) * time.Second,
		DnsMsg:       resp,
	}

	// Add records to the corresponding fields
	for _, answer := range resp.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			if a, ok := answer.(*dns.A); ok {
				entry.IPv4 = append(entry.IPv4, a.A)
			}
		case dns.TypeAAAA:
			if aaaa, ok := answer.(*dns.AAAA); ok {
				entry.IPv6 = append(entry.IPv6, aaaa.AAAA)
			}
		}
	}

	// Bind entry to the cache
	//cache.GlobalCache.RLock()
	// Bind entry to the cache
	cache.GlobalCache.RLock()
	defer cache.GlobalCache.RUnlock()
	cache.GlobalCache.Store[cache.GenerateCacheKey(hostName, question.Qtype)] = entry
	//cache.GlobalCache.RUnlock()
}

// GetQTypeAnswer - Get answer for allowed Qtype
func GetQTypeAnswer(hostName string, question dns.Question, upstreamAddr string) ([]dns.RR, error) {

	// NOTE: Need enable if this func will calls from another func (except DNS handler)
	//key := cache.GenerateCacheKey(hostName, question.Qtype)
	// Check if the result is in the cache
	////cache.GlobalCache.RLock()
	//if entry, found := cache.CheckCache(hostName, question.Qtype); found {
	//	log.Printf("Cache hit for %s\n", hostName)
	//	prom.CacheHitResponseTotal.Inc()
	//	defer cache.CheckAndDeleteExpiredEntries()
	//	return entry.DnsMsg.Answer, nil
	//}
	////cache.GlobalCache.RUnlock()

	client := dns.Client{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(hostName), question.Qtype)

	var records []string

	switch question.Qtype {
	case dns.TypeA:
		respA, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respA.Answer) > 0 {
			// Add records to the corresponding cache fields
			bindAnswerCache(respA, hostName, question)
			return respA.Answer, nil
		}
	case dns.TypeAAAA:
		respAAAA, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respAAAA.Answer) > 0 {
			bindAnswerCache(respAAAA, hostName, question)
			return respAAAA.Answer, nil
		}
	case dns.TypeHTTPS:
		respHTTPS, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}
		if err == nil && len(respHTTPS.Answer) > 0 {
			bindAnswerCache(respHTTPS, hostName, question)
			return respHTTPS.Answer, nil
		}
	case dns.TypeCNAME:
		//m.SetQuestion(hostName, question.Qtype)
		respCNAME, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respCNAME.Answer) > 0 {
			return respCNAME.Answer, nil
		} else {

			// Process answers depending on the record type
			for _, answer := range respCNAME.Ns {
				switch question.Qtype {
				case dns.TypeCNAME:
					if cname, ok := answer.(*dns.CNAME); ok {
						records = append(records, cname.Target)
					}
					if hasSOARecords(respCNAME) {
						// Process SOA records and add them to the answer
						processSOA(respCNAME.Ns, m)
						return m.Answer, nil
					}
				case dns.TypeSOA:
					if soa, ok := answer.(*dns.SOA); ok {
						records = append(records, fmt.Sprintf("Primary: %s, Responsible: %s", soa.Ns, soa.Mbox))
					}
				default:
					return nil, fmt.Errorf("unsupported record type: %d", question.Qtype)
				}
			}
		}
	case dns.TypeNS:
		respNS, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respNS.Answer) > 0 {
			return respNS.Answer, nil
		}
	case dns.TypeMX:
		respMX, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respMX.Answer) > 0 {
			return respMX.Answer, nil
		}
	case dns.TypePTR:
		respPTR, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respPTR.Answer) > 0 {
			return respPTR.Answer, nil
		} else {

			if hasSOARecords(respPTR) {
				processSOA(respPTR.Ns, m)
				return m.Answer, nil
			}
		}
	case dns.TypeSOA:
		respSOA, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respSOA.Answer) > 0 {
			return respSOA.Answer, nil
		} else {

			if hasSOARecords(respSOA) {
				processSOA(respSOA.Ns, m)
				return m.Answer, nil
			}
		}
	case dns.TypeSRV:
		respSRV, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respSRV.Answer) > 0 {
			return respSRV.Answer, nil
		} else {
			if hasSOARecords(respSRV) {
				processSOA(respSRV.Ns, m)
				return m.Answer, nil
			}
		}
	//TODO: TXT in a testing status, need to recheck this
	case dns.TypeTXT:
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(hostName), dns.TypeTXT)
		c := new(dns.Client)
		response, _, err := c.Exchange(msg, upstreamAddr)
		if err != nil {
			return nil, err
		}
		log.Println("TXT response:", response)

		respTXT, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respTXT.Answer) > 0 {
			return respTXT.Answer, nil
		} else {
			if hasSOARecords(respTXT) {
				processSOA(respTXT.Ns, m)
				return m.Answer, nil
			}
		}
	// Another requests type
	default:
		return nil, fmt.Errorf("unsupported DNS query type: %d", question.Qtype)
	}

	return nil, nil
}
