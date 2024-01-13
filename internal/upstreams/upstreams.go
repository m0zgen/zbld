package upstreams

import (
	"github.com/miekg/dns"
	"log"
	"net"
	"time"
	"zdns/internal/cache"
	prom "zdns/internal/prometheus"
)

// Config structure for storing configuration parameters
var CurrentIndex = 0

// Functions for internal use
// Check if upstream DNS server is available
func isUpstreamServerAvailable(upstreamAddr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("udp", upstreamAddr, timeout)
	if err != nil {
		return false
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Printf("Error closing connection: %v", err)
			return // ignore error
		}
	}(conn)
	return true
}

// Strict upstream balancing policy
func getNextUpstreamServer(upstreams []string) string {

	// Проверить доступность первого сервера
	if isUpstreamServerAvailable(upstreams[0], 2*time.Second) {
		return upstreams[0]
	}

	// Если первый сервер недоступен, вернуть второй
	return upstreams[1]
}

// Round-robin upstream balancing policy
func getRobinUpstreamServer(upstreams []string) string {
	//mu.Lock()
	//defer mu.Unlock()
	// Простой round-robin: выбираем следующий сервер
	CurrentIndex = (CurrentIndex + 1) % len(upstreams)
	return upstreams[CurrentIndex]
}

// Functions for external use
// Get upstream server and apply balancing strategy (call from DNS handler
func GetUpstreamServer(upstreams []string, balancingPolicy string) string {

	switch balancingPolicy {
	case "robin":
		log.Println("Round-robin strategy")
		return getRobinUpstreamServer(upstreams)
	case "strict":
		log.Println("Strict strategy")
		return getNextUpstreamServer(upstreams)
	default:
		// Default strategy is robin
		log.Println("Default strategy (robin)")
		return getRobinUpstreamServer(upstreams)
	}

}

// Resolve both IPv4 and IPv6 addresses using upstream DNS with selected balancing strategy
func ResolveBothWithUpstream(host string, clientIP net.IP, upstreamAddr string, cacheEnabled bool, cacheTTLSeconds int) (net.IP, net.IP) {

	if cacheEnabled {
		//log.Println("Cache enabled")
		cache.GlobalCache.RLock()
		entry, exists := cache.GlobalCache.Store[host]
		cache.GlobalCache.RUnlock()

		if exists {
			log.Printf("Cache hit for %s\n", host)
			prom.CacheHitResponseTotal.Inc()
			// Check and delete expired TTL entries from cache
			defer cache.CheckAndDeleteExpiredEntries()
			return entry.IPv4, entry.IPv6
		}
	}

	// If cache does not contain entry for this host, resolve it with upstream DNS
	client := dns.Client{}
	var ipv4, ipv6 net.IP

	// Iterate over upstream DNS servers
	// TODO: Add primary adn secondary upstream DNS servers or select random one from list
	//for _, upstreamAddr := range config.UpstreamDNSServers {

	// Resolve IPv4
	msgIPv4 := &dns.Msg{}
	msgIPv4.SetQuestion(dns.Fqdn(host), dns.TypeA)
	log.Println("Resolving with upstream DNS for IPv4:", upstreamAddr, clientIP, host)

	respIPv4, _, err := client.Exchange(msgIPv4, upstreamAddr)
	if err == nil && len(respIPv4.Answer) > 0 {

		//if a, ok := respIPv4.Answer[0].(*dns.A); ok {
		//	ipv4 = a.A
		//	//break
		//}
		for _, answer := range respIPv4.Answer {
			if a, ok := answer.(*dns.A); ok {
				ipv4 = a.A
				log.Printf("IPv4 address: %s\n", ipv4)
			}
		}

		//}

		// Resolve IPv6
		msgIPv6 := &dns.Msg{}
		msgIPv6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)

		log.Println("Resolving with upstream DNS for IPv6:", upstreamAddr, clientIP, host)

		respIPv6, _, err := client.Exchange(msgIPv6, upstreamAddr)

		if err == nil && len(respIPv6.Answer) > 0 {
			//if aaaa, ok := respIPv6.Answer[0].(*dns.AAAA); ok {
			//	ipv6 = aaaa.AAAA
			//	//break
			//}
			for _, answer := range respIPv6.Answer {
				if aaaa, ok := answer.(*dns.AAAA); ok {
					ipv6 = aaaa.AAAA
					log.Printf("IPv6 address: %s\n", ipv6)
				}
			}
		}
	}

	// Return the default IP addresses if no successful response is obtained
	//if ipv4 == nil {
	//	ipv4 = net.ParseIP(config.DefaultIPAddress)
	//}
	//if ipv6 == nil {
	//	ipv6 = net.ParseIP(config.DefaultIPAddress)
	//}

	// Вернуть nil для ipv6, если AAAA запись отсутствует
	if ipv6.Equal(net.ParseIP("::ffff:0.0.0.0")) {
		ipv6 = nil
	}

	if ipv4 != nil && !ipv6.Equal(net.ParseIP("::ffff:0.0.0.0")) {
		// Домен имеет запись A (IPv4), но не имеет записи AAAA (IPv6)
		log.Printf("Domain %s has A address %s\n", host, ipv4.String())
	} else {
		// Домен либо не имеет записи A (IPv4), либо имеет запись AAAA (IPv6)
		log.Printf("Domain %s does not have A address\n", host)
	}

	if cacheEnabled {
		// Обновление кэша
		cache.GlobalCache.RLock()
		cache.GlobalCache.Store[host] = cache.CacheEntry{IPv4: ipv4, IPv6: ipv6}
		entry := cache.GlobalCache.Store[host]
		entry.UpdateCreationTimeWithTTL(time.Duration(cacheTTLSeconds) * time.Second)
		cache.GlobalCache.Store[host] = entry
		cache.GlobalCache.RUnlock()
	}

	return ipv4, ipv6
}
