package queries

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
	"zbld/internal/cache"
	configuration "zbld/internal/config"
	"zbld/internal/global"
	prom "zbld/internal/prometheus"
)

var configCacheTTLSeconds int
var configTruncateMessages bool

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
// and set configuration parameters to local variables
func SetConfig(cfg *configuration.Config) {
	// Set local variables through cgf.Config
	configCacheTTLSeconds = cfg.CacheTTLSeconds
	configTruncateMessages = cfg.TruncateMessages
	// ...
}

// Local functions ---------------------------------------------------------- //

// qTypeToString - QType unit converter
func qTypeToString(qtype uint16) string {
	switch qtype {
	case dns.TypeA:
		return "TypeA"
	case dns.TypeAAAA:
		return "TypeAAAA"
	case dns.TypeCNAME:
		return "TypeCNAME"
	case dns.TypeNS:
		return "TypeNS"
	case dns.TypeMX:
		return "TypeMX"
	case dns.TypePTR:
		return "TypePTR"
	case dns.TypeSOA:
		return "TypeSOA"
	case dns.TypeSRV:
		return "TypeSRV"
	default:
		return fmt.Sprintf("UnknownType%d", qtype)
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

// processSOA - Process SOA records and add them to the answer
func processSOA(answerRR []dns.RR, m *dns.Msg) {
	for _, rr := range answerRR {
		if soa, ok := rr.(*dns.SOA); ok {
			// Extract needed data from SOA record
			// As example: soa.Ns, soa.Mbox, soa.Serial etc.
			// Then add this data to the answer
			m.Ns = append(m.Answer, &dns.SOA{
				Hdr: dns.RR_Header{
					Name:     m.Question[0].Name,
					Rrtype:   dns.TypeSOA,
					Class:    dns.ClassINET,
					Rdlength: soa.Hdr.Rdlength,
					Ttl:      soa.Hdr.Ttl},
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
func processResponse(m *dns.Msg, resp *dns.Msg, key string, err error) ([]dns.RR, bool, error) {
	if err != nil {
		return nil, false, err
	}

	var isAnswerExist = false

	if len(resp.Answer) > 0 {
		cache.WriteToCache(key, createCacheEntryFromA(resp))
		isAnswerExist = true
		return resp.Answer, isAnswerExist, nil
	}

	if hasSOARecords(resp) {
		processSOA(resp.Ns, m)
		cache.WriteToCache(key, createCacheEntryFromSOA(m))
		return m.Ns, isAnswerExist, nil
	}

	return nil, isAnswerExist, nil
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

// SetEDNSOptions - Set EDNS options
func SetEDNSOptions(m *dns.Msg, size uint16, do bool) {
	edns := new(dns.OPT)
	edns.Hdr.Name = "."
	edns.Hdr.Rrtype = dns.TypeOPT
	edns.SetUDPSize(size)
	edns.SetDo(do)
	m.Extra = append(m.Extra, edns)
}

// GetQTypeAnswer - Get answer for allowed Qtype
func GetQTypeAnswer(hostName string, question dns.Question, upstreamAddr string, clientTCP bool) ([]dns.RR, bool, error) {

	m := &dns.Msg{}
	SetEDNSOptions(m, 4096, true)
	m.SetQuestion(dns.Fqdn(hostName), question.Qtype)
	client := dns.Client{}
	if clientTCP {
		client.Net = "tcp"
	}
	resp, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Println("Error getting QType answer from client exchange (trying on TCP):", err)
		//return nil, err
	}

	if resp != nil && resp.Truncated {
		client.Net = "tcp"
		if configTruncateMessages {
			global.IsFromTCP = true
		}
		log.Println("Truncated response, trying on TCP")
		resp, _, err = client.Exchange(m, upstreamAddr)
		if err != nil {
			log.Println("Error get QType answer from client in TCP:", err)
			return nil, false, err
		}
	}

	key := cache.GenerateCacheKey(hostName, question.Qtype)

	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeNS, dns.TypeMX, dns.TypePTR, dns.TypeSOA, dns.TypeSRV:
		prom.IncrementRequestsQTypeTotal(qTypeToString(question.Qtype))
		return processResponse(m, resp, key, err)

	case dns.TypeHTTPS:
		respHTTPS, _, errHS := client.Exchange(m, upstreamAddr)
		if errHS != nil {
			// Try TypeA query if HTTPS query fails
			m.SetQuestion(hostName, dns.TypeA)
			respConvA, _, errConv := client.Exchange(m, upstreamAddr)
			return processResponse(m, respConvA, key, errConv)
		}

		if len(respHTTPS.Answer) > 0 {
			if respHTTPS.Answer[0].Header().Rrtype == dns.TypeCNAME {
				// Convert CNAME to TypeA query
				cname := respHTTPS.Answer[0].(*dns.CNAME)
				m.SetQuestion(cname.Target, dns.TypeA)
				respConvA, _, errConv := client.Exchange(m, upstreamAddr)
				return processResponse(m, respConvA, key, errConv)
			}
			// Cache HTTPS answer
			cache.WriteToCache(key, createCacheEntryFromA(respHTTPS))
			return respHTTPS.Answer, false, nil
		} else {
			// Try TypeA query if HTTPS answer is empty
			m.SetQuestion(hostName, dns.TypeA)
			respConvA, _, errConv := client.Exchange(m, upstreamAddr)
			return processResponse(m, respConvA, key, errConv)
		}
	//TODO: TXT in a testing status, need to recheck this
	case dns.TypeTXT:
		// Check if the response has TXT records / errors
		if err != nil {
			return nil, false, err

		}
		// Check if the response has TXT records
		if len(resp.Answer) == 0 {
			return nil, false, fmt.Errorf("no answers for TXT query")
		}

		return resp.Answer, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported DNS query type: %d", question.Qtype)
	}

	//return nil, false, nil

}
