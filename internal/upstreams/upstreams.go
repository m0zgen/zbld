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

	// Check if first upstream server is available
	if isUpstreamServerAvailable(upstreams[0], 2*time.Second) {
		return upstreams[0]
	}

	// If first upstream server is not available, return second one
	return upstreams[1]
}

// Round-robin upstream balancing policy
func getRobinUpstreamServer(upstreams []string) string {
	//mu.Lock()
	//defer mu.Unlock()
	// Simple round-robin: select next server
	CurrentIndex = (CurrentIndex + 1) % len(upstreams)
	//log.Println("CurrentIndex: ", CurrentIndex)
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
