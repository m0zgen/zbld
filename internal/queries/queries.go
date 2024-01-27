package queries

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
	"zdns/internal/cache"
	configuration "zdns/internal/config"
	"zdns/internal/prometheus"
)

var configCacheTTLSeconds int

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
// and set configuration parameters to local variables
func SetConfig(cfg *configuration.Config) {
	// Set local variables through cgf.Config
	configCacheTTLSeconds = cfg.CacheTTLSeconds
	// ...
}

// Local functions ---------------------------------------------------------- //

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

// processResponse - Process response and return answer
func processResponse(m *dns.Msg, resp *dns.Msg, key string, err error) ([]dns.RR, error) {

	if err != nil {
		return nil, err
	}

	if len(resp.Answer) > 0 {
		cache.WriteToCache(key, createCacheEntryFromA(resp))
		return resp.Answer, nil
	}

	if hasSOARecords(resp) {
		processSOA(resp.Ns, m)
		cache.WriteToCache(key, createCacheEntryFromSOA(m))
		return m.Answer, nil
	}

	return nil, nil
}

// Caching functions -------------------------------------------------------- //

// createCacheEntryFromSOA - Create cache entry from SOA records
func createCacheEntryFromSOA(resp *dns.Msg) *cache.CacheEntry {

	entry := &cache.CacheEntry{
		IPv4:         []net.IP{},
		IPv6:         []net.IP{},
		CreationTime: time.Now(),
		//TTL:          time.Duration(resp.Answer[0].Header().Ttl) * time.Second,
		TTL:    time.Duration(configCacheTTLSeconds) * time.Second,
		DnsMsg: resp,
	}

	return entry
}

// createCacheEntryFromA - Create cache entry from A records
func createCacheEntryFromA(resp *dns.Msg) *cache.CacheEntry {
	// Create cache entry
	entry := &cache.CacheEntry{
		IPv4:         []net.IP{},
		IPv6:         []net.IP{},
		CreationTime: time.Now(),
		//TTL:          time.Duration(resp.Answer[0].Header().Ttl) * time.Second,
		TTL:    time.Duration(configCacheTTLSeconds) * time.Second,
		DnsMsg: resp,
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

	return entry
}

// External functions ------------------------------------------------------- //

// GetQTypeAnswer - Get answer for allowed Qtype
func GetQTypeAnswer(hostName string, question dns.Question, upstreamAddr string) ([]dns.RR, error) {

	key := cache.GenerateCacheKey(hostName, question.Qtype)
	client := dns.Client{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(hostName), question.Qtype)

	switch question.Qtype {
	case dns.TypeA:
		respA, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}
		if err == nil && len(respA.Answer) > 0 {
			cache.WriteToCache(key, createCacheEntryFromA(respA))
			// Инкрементируем метрику в горутине
			prom.IncrementRequestsQTypeTotal("TypeA")
			return respA.Answer, nil
		}
	case dns.TypeAAAA:
		respAAAA, _, err := client.Exchange(m, upstreamAddr)
		//defer prom.RequestsQTypeTotal.WithLabelValues("TypeAAAA").Inc()
		// Increment metric in a goroutine
		prom.IncrementRequestsQTypeTotal("TypeAAAA")
		return processResponse(m, respAAAA, key, err)
	case dns.TypeHTTPS:
		respHTTPS, _, err := client.Exchange(m, upstreamAddr)
		if err != nil {
			return nil, err
		}

		if err == nil && len(respHTTPS.Answer) > 0 {

			if respHTTPS.Answer[0].Header().Rrtype == dns.TypeCNAME {
				log.Println("CNAME record found for:", hostName)
				m.SetQuestion(respHTTPS.Answer[0].Header().Name, dns.TypeA)
				respConvCN, _, errConv := client.Exchange(m, upstreamAddr)
				if errConv != nil {
					log.Printf("Failed to get TypeA response for %s. Error: %v\n", hostName, errConv)
					return nil, errConv
				}
				return respConvCN.Answer, nil
			}
			cache.WriteToCache(key, createCacheEntryFromA(respHTTPS))
			return respHTTPS.Answer, nil
		} else {
			// Re-request as TypeA
			m.SetQuestion(hostName, dns.TypeA)
			respConvA, _, errConv := client.Exchange(m, upstreamAddr)
			if errConv != nil {
				log.Printf("Failed to get TypeA response for %s. Error: %v\n", hostName, errConv)
				return nil, errConv
			}
			m.Answer = respConvA.Answer
			return respConvA.Answer, nil
			//if hasSOARecords(respHTTPS) {
			//	processA(respHTTPS.Ns, m)
			//	return m.Answer, nil
			//}
		}
	case dns.TypeCNAME:
		respCNAME, _, err := client.Exchange(m, upstreamAddr)
		return processResponse(m, respCNAME, key, err)
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
		return processResponse(m, respPTR, key, err)
	case dns.TypeSOA:
		respSOA, _, err := client.Exchange(m, upstreamAddr)
		return processResponse(m, respSOA, key, err)
	case dns.TypeSRV:
		respSRV, _, err := client.Exchange(m, upstreamAddr)
		return processResponse(m, respSRV, key, err)
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
				cache.WriteToCache(key, createCacheEntryFromSOA(m))
				return m.Answer, nil
			}
		}
	default:
		return nil, fmt.Errorf("unsupported DNS query type: %d", question.Qtype)
	}

	return nil, nil
}
