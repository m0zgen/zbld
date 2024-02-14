package upstreams

import (
	"github.com/miekg/dns"
	"log"
	"time"
	configuration "zbld/internal/config"
)

// Variables --------------------------------------------------------------- //

// CurrentIndex - Selected upstream server index
var CurrentIndex = 0

var bootstrapServers []string
var checkAvailableDomain string

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
// and set configuration parameters to local variables
func SetConfig(cfg *configuration.Config) {
	// Set local variables through cgf.Config
	bootstrapServers = cfg.BootstrapDNSServers
	checkAvailableDomain = cfg.CheckAvailableDomain
	// ...
}

// Functions for internal use ---------------------------------------------- //

// checkUpstreamAvailabilityOverDNS - Check if upstream DNS server is available
func checkUpstreamAvailabilityOverDNS(upstreamAddr string, timeout time.Duration) bool {
	// Create DNS client
	client := dns.Client{Timeout: timeout}

	// Create a request to check availability
	m := new(dns.Msg)
	m.SetQuestion(checkAvailableDomain, dns.TypeA)

	// Send a request to the upstream
	_, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("Error checking upstream availability: %v\n", err)
		return false
	}

	// If there is no error, the upstream is available
	return true
}

// getNextUpstreamServer - Strict upstream balancing policy
func getNextUpstreamServer(upstreams []string) string {

	// Check if first upstream server is available (seconds 1*time.Second, milliseconds 1000*time.Millisecond
	for _, upstream := range upstreams {
		if checkUpstreamAvailabilityOverDNS(upstream, 200*time.Millisecond) {
			return upstream
		}
	}

	// If upstreams not available, try to use bootstrap servers
	for _, bootstrap := range bootstrapServers {
		if checkUpstreamAvailabilityOverDNS(bootstrap, 1*time.Second) {
			return bootstrap
		}
	}

	// If none of the servers are available, return an error or a default value
	return ""
}

// getRobinUpstreamServer - Round-robin upstream balancing policy
func getRobinUpstreamServer(upstreams []string) string {
	for i := 0; i < len(upstreams); i++ {
		// Get current index with round-robin
		currentIndex := (CurrentIndex + i) % len(upstreams)
		// Check if current upstream server is available
		if checkUpstreamAvailabilityOverDNS(upstreams[currentIndex], 500*time.Millisecond) {
			return upstreams[currentIndex]
		}
	}
	// If none of the upstreams are available, use bootstrap upstream
	for _, bootstrap := range bootstrapServers {
		if checkUpstreamAvailabilityOverDNS(bootstrap, 500*time.Millisecond) {
			return bootstrap
		}
	}
	// if bootstrap upstream is not available, return an error or a default value
	return ""
}

// Functions for external usage ---------------------------------------------- //

// GetUpstreamServer - Get upstream server and apply balancing strategy (call from DNS handler
func GetUpstreamServer(upstreams []string, balancingPolicy string) string {

	switch balancingPolicy {
	case "robin":
		//log.Println("Round-robin strategy")
		return getRobinUpstreamServer(upstreams)
	case "strict":
		//log.Println("Strict strategy")
		return getNextUpstreamServer(upstreams)
	default:
		// Default strategy is robin
		//log.Println("Default strategy (robin)")
		return getRobinUpstreamServer(upstreams)
	}

}
