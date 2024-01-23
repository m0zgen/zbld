package deprecation

import (
	"github.com/miekg/dns"
	"net"
)

// Queries ------------------------------------------------------------------ //

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

// Upstreams ---------------------------------------------------------------- //

// ReturnZeroIP - Return zero IP address for blocked domains
//func ReturnZeroIP(m *dns.Msg, clientIP net.IP, host string) []dns.RR {
//
//	// Return 0.0.0.0 for names in hosts.txt
//	answer := dns.A{
//		Hdr: dns.RR_Header{
//			Name:   host,
//			Rrtype: dns.TypeA,
//			Class:  dns.ClassINET,
//			Ttl:    0,
//		},
//		A: net.ParseIP("0.0.0.0"),
//	}
//	m.Answer = append(m.Answer, &answer)
//	log.Println("Zero response for:", clientIP, host)
//	prom.ZeroResolutionsTotal.Inc()
//	return m.Answer
//
//}

// ResolveBothWithUpstream - Resolve both IPv4 and IPv6 addresses using upstream DNS with selected balancing strategy
//func ResolveBothWithUpstream(host string, clientIP net.IP, upstreamAddr string, cacheEnabled bool, cacheTTLSeconds int) ([]net.IP, []net.IP, *dns.Msg) {
//
//	if cacheEnabled {
//		//log.Println("Cache enabled")
//		cache.GlobalCache.RLock()
//		entry, exists := cache.GlobalCache.Store[host]
//		cache.GlobalCache.RUnlock()
//
//		if exists {
//			log.Printf("Cache hit for %s\n", host)
//			prom.CacheHitResponseTotal.Inc()
//			// Check and delete expired TTL entries from cache
//			defer cache.CheckAndDeleteExpiredEntries()
//			return entry.IPv4, entry.IPv6, entry.DnsMsg
//		}
//	}
//
//	// If cache does not contain entry, resolve it with upstream DNS
//	client := dns.Client{}
//	var ipv4, ipv6 []net.IP
//
//	// Resolve IPv4
//	msgIPv4 := &dns.Msg{}
//	msgIPv4.SetQuestion(dns.Fqdn(host), dns.TypeA)
//	log.Println("Resolving with upstream DNS for IPv4:", upstreamAddr, clientIP, host)
//
//	respIPv4, _, err := client.Exchange(msgIPv4, upstreamAddr)
//	if err == nil && len(respIPv4.Answer) > 0 {
//
//		//if a, ok := respIPv4.Answer[0].(*dns.A); ok {
//		//	ipv4 = a.A
//		//	//break
//		//}
//		//
//		for _, answer := range respIPv4.Answer {
//			if a, ok := answer.(*dns.A); ok {
//				//ipv4 = a.A
//				ipv4 = append(ipv4, a.A)
//				log.Printf("IPv4 address: %s\n", ipv4)
//			}
//		}
//
//		//}
//	}
//
//	// Resolve IPv6
//	msgIPv6 := &dns.Msg{}
//	msgIPv6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
//	log.Println("Resolving with upstream DNS for IPv6:", upstreamAddr, clientIP, host)
//
//	respIPv6, _, err := client.Exchange(msgIPv6, upstreamAddr)
//	if err == nil && len(respIPv6.Answer) > 0 {
//		//if aaaa, ok := respIPv6.Answer[0].(*dns.AAAA); ok {
//		//	ipv6 = aaaa.AAAA
//		//	//break
//		//}
//		//
//		for _, answer := range respIPv6.Answer {
//			if aaaa, ok := answer.(*dns.AAAA); ok {
//				//ipv6 = aaaa.AAAA
//				ipv6 = append(ipv6, aaaa.AAAA)
//				log.Printf("IPv6 address: %s\n", ipv6)
//			}
//		}
//	}
//
//	// Return the default IP addresses if no successful response is obtained
//	//if ipv4 == nil {
//	//	ipv4 = net.ParseIP(config.DefaultIPAddress)
//	//}
//	//if ipv6 == nil {
//	//	ipv6 = net.ParseIP(config.DefaultIPAddress)
//	//}
//
//	// Return nil for ipv6, if AAAA record is not found
//	//for addr := range ipv6 {
//	//
//	//	if addr.Equal(net.ParseIP("::ffff:")) {
//	//				ipv6 = nil
//	//	}
//	//
//	//	if addr.Equal(net.ParseIP("::ffff:0.0.0.0")) {
//	//		ipv6 = nil
//	//	}
//	//}
//
//	if ipv4 != nil && ipv6 != nil {
//		// Domain has A (IPv4), but does not have AAAA (IPv6)
//		log.Printf("Domain %s has A address %s\n", host, ipv4)
//	} else {
//		// The domain either does not have an A record (IPv4) or has an AAAA record (IPv6)
//		log.Printf("Domain %s does not have A address\n", host)
//		//rCode := respIPv4.MsgHdr.Rcode
//	}
//
//	// Update cache if enabled
//	if cacheEnabled {
//		cache.GlobalCache.RLock()
//		cache.GlobalCache.Store[host] = cache.CacheEntry{IPv4: ipv4, IPv6: ipv6, DnsMsg: respIPv4}
//		entry := cache.GlobalCache.Store[host]
//		entry.UpdateCreationTimeWithTTL(time.Duration(cacheTTLSeconds) * time.Second)
//		cache.GlobalCache.Store[host] = entry
//		cache.GlobalCache.RUnlock()
//	}
//
//	return ipv4, ipv6, respIPv4
//}

// Another comments	-------------------------------------------------------- //

// getQTypeResponse
//ipv4, ipv6, _ := upstreams.ResolveBothWithUpstream(host, clientIP, upstreamAd, config.CacheEnabled, config.CacheTTLSeconds)
//log.Println("Caching answer for:", host, ipv4, ipv6)

//switch question.Qtype {
//case dns.TypeA:
//	aAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if aAnswer != nil {
//		m.Answer = append(m.Answer, aAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for A:", aAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//case dns.TypeAAAA:
//	aaaaAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if aaaaAnswer != nil {
//		m.Answer = append(m.Answer, aaaaAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for AAAA:", aaaaAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//case dns.TypeCNAME:
//	cnameAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if cnameAnswer != nil {
//		m.Answer = append(m.Answer, cnameAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for CNAME:", cnameAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//case dns.TypeNS:
//
//
//}

//if ipv4 != nil {
//if question.Qtype == dns.TypeA {
//	aAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if aAnswer != nil {
//		m.Answer = append(m.Answer, aAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for A:", aAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//
//	//
//	//for addr := range ipv4 {
//	//	log.Println("IPv4 addr:", ipv4[addr])
//	//	answer := queries.GetAv4(ipv4[addr], host, question)
//	//	if answer != nil {
//	//		m.Answer = append(m.Answer, answer)
//	//		if config.IsDebug {
//	//			log.Println("Answer v4:", answer)
//	//		}
//	//		prom.SuccessfulResolutionsTotal.Inc()
//	//	} else {
//	//		setResponseCode(m, resp.MsgHdr.Rcode)
//	//	}
//	//
//	//}
//}
//if question.Qtype == dns.TypeAAAA {
//	aaaaAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if aaaaAnswer != nil {
//		m.Answer = append(m.Answer, aaaaAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for AAAA:", aaaaAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypeCNAME {
//	cnameAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if cnameAnswer != nil {
//		m.Answer = append(m.Answer, cnameAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for CNAME:", cnameAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//
//}
//if question.Qtype == dns.TypeNS {
//	nsAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if nsAnswer != nil {
//		m.Answer = append(m.Answer, nsAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for NS:", nsAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypeMX {
//	mxAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if mxAnswer != nil {
//		m.Answer = append(m.Answer, mxAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for MX:", mxAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypeSOA {
//	soaAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if soaAnswer != nil {
//		m.Answer = append(m.Answer, soaAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for SOA:", soaAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypeSRV {
//	srvAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if srvAnswer != nil {
//		m.Answer = append(m.Answer, srvAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for SRV:", srvAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypePTR {
//	ptrAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if ptrAnswer != nil {
//		m.Answer = append(m.Answer, ptrAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for PTR:", ptrAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}
//if question.Qtype == dns.TypeTXT {
//	txtAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
//	if txtAnswer != nil {
//		m.Answer = append(m.Answer, txtAnswer...)
//		if config.IsDebug {
//			log.Println("Answer for TXT:", txtAnswer)
//		}
//		prom.SuccessfulResolutionsTotal.Inc()
//	} else {
//		setResponseCode(m, dns.RcodeNameError)
//	}
//}

// IPv6
//if ipv6 != nil {
//	if question.Qtype == dns.TypeAAAA {
//		if ipv6 != nil {
//			for addr := range ipv6 {
//				log.Println("IPv6 addr:", ipv6[addr])
//				answer := queries.GetAAAAv6(ipv6[addr], host, question)
//				if answer != nil {
//					m.Answer = append(m.Answer, answer)
//					prom.SuccessfulResolutionsTotal.Inc()
//				} else {
//					setResponseCode(m, resp.MsgHdr.Rcode)
//				}
//
//			}
//			//answerIPv6 := dns.AAAA{
//			//	Hdr: dns.RR_Header{
//			//		Name:   host,
//			//		Rrtype: dns.TypeAAAA,
//			//		Class:  dns.ClassINET,
//			//		Ttl:    0,
//			//	},
//			//	AAAA: ipv6,
//			//}
//			//m.Answer = append(m.Answer, &answerIPv6)
//			//log.Println("Answer v6:", answerIPv6)
//			//prom.SuccessfulResolutionsTotal.Inc()
//		}
//	}
//} else {
//	// If IPv6 address is not available, set response code to code from MsgHdr.Rcode
//	//log.Println("MsgHdr.Rcode from resp:", resp.MsgHdr.Rcode)
//	setResponseCode(m, resp.MsgHdr.Rcode)
//}
//} else {
//	// If Qtype is not allowed, set response code to 5 (Refused)
//	log.Println("Qtype is not allowed:", question.Qtype)
//	setResponseCode(m, 5)
//}

//if config.IsDebug {
//	log.Println("Response:", resp)
//}

// handleDNSRequest
// var upstreamAd string
// Check inverse and matching
//if isMatching(_host, regexMap) {
//	if config.Inverse {
//		returnZeroIP(m, clientIP, host)
//	} else {
//		log.Println("Resolving with upstream DNS as RegEx:", clientIP, _host)
//		getQTypeResponse(m, question, host, clientIP, _host, upstreamAd)
//	}
//} else if hosts[_host] {
//	if config.Inverse {
//		returnZeroIP(m, clientIP, host)
//	} else {
//		log.Println("Resolving with upstream DNS as simple line:", clientIP, _host)
//		getQTypeResponse(m, question, host, clientIP, _host, upstreamAd)
//	}
//} else {
//	if config.Inverse {
//		log.Println("Resolving with upstream DNS for:", clientIP, _host)
//		getQTypeResponse(m, question, host, clientIP, _host, upstreamAd)
//	} else {
//		returnZeroIP(m, clientIP, host)
//	}
//}

// CheckAndDeleteExpiredEntries - Check and delete expired TTL entries from cache
//func CheckAndDeleteExpiredEntries() {
//	// Check and delete expired TTL entries from cache
//	GlobalCache.mu.Lock()
//	defer GlobalCache.mu.Unlock()
//
//	keysToDelete := []string{}
//
//	for key, entry := range GlobalCache.Store {
//		if time.Since(entry.CreationTime) > entry.TTL {
//			keysToDelete = append(keysToDelete, key)
//		}
//	}
//
//	// Delete after iteration
//	for _, key := range keysToDelete {
//		delete(GlobalCache.Store, key)
//	}
//}
