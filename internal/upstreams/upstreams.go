package upstreams

import (
	"log"
	"net"
	"time"
)

// Variables --------------------------------------------------------------- //

// CurrentIndex - Selected upstream server index
var CurrentIndex = 0

// Functions for internal use ---------------------------------------------- //

// isUpstreamServerAvailable - Check if upstream DNS server is available
func isUpstreamServerAvailable(upstreamAddr string, timeout time.Duration) bool {

	conn, err := net.DialTimeout("udp", upstreamAddr, timeout)
	if err != nil {
		return false
	}
	defer func(conn net.Conn) {
		err := conn.Close()
		if err != nil {
			log.Println("Error closing connection:", err)
			return // ignore error
		}
	}(conn)
	return true
}

// getNextUpstreamServer - Strict upstream balancing policy
func getNextUpstreamServer(upstreams []string) string {

	// Check if first upstream server is available
	if isUpstreamServerAvailable(upstreams[0], 2*time.Second) {
		return upstreams[0]
	}

	// If first upstream server is not available, return second one
	return upstreams[1]
}

// getRobinUpstreamServer - Round-robin upstream balancing policy
func getRobinUpstreamServer(upstreams []string) string {
	CurrentIndex = (CurrentIndex + 1) % len(upstreams)
	return upstreams[CurrentIndex]
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
