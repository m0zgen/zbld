package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
	"zdns/internal/cache"
	"zdns/internal/config"
	"zdns/internal/lists"
	"zdns/internal/prometheus"
	"zdns/internal/queries"
	"zdns/internal/upstreams"
	"zdns/internal/usermgmt"
)

// Global Variables ----------------------------------------------------------- //
var config configuration.Config
var hosts map[string]bool
var permanentHosts map[string]bool
var regexMap map[string]*regexp.Regexp
var permanentRegexMap map[string]*regexp.Regexp
var mu sync.Mutex

//var upstreamServers []string

// Process DNS queries ------------------------------------------------------- //

// handleCacheHit - Handle cache hit
func entryInCache(m *dns.Msg, host string, question dns.Question) bool {

	// Read from cache
	if entry, found := cache.CheckCache(host, question.Qtype); found {
		log.Println("Cache hit from handler for:", host)
		m.Answer = append(m.Answer, entry.DnsMsg.Answer...)
		if config.IsDebug {
			log.Printf("Answer: %s\n", entry.DnsMsg.Answer)
		}
		defer prom.CacheHitResponseTotal.Inc()
		return true
	}
	return false
}

// setResponseCode - Set DNS response code
func setResponseCode(m *dns.Msg, responseCode int) {

	// Case if error code from 1 to 5
	// 1 - Format error - The name server was unable to interpret the query.
	// 2 - Server failure - The name server was unable to process this query due to a problem with the name server.
	// 3 - Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	// 4 - Not Implemented - The name server does not support the requested kind of query.
	// 5 - Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.

	// Check if response code is valid
	if responseCode >= dns.RcodeSuccess && responseCode <= dns.RcodeBadName {

		switch responseCode {
		case 0:
			m.SetRcode(m, dns.RcodeSuccess)
		case 1:
			m.SetRcode(m, dns.RcodeFormatError)
		case 2:
			m.SetRcode(m, dns.RcodeServerFailure)
		case 3:
			m.SetRcode(m, dns.RcodeNameError)
		case 4:
			m.SetRcode(m, dns.RcodeNotImplemented)
		case 5:
			m.SetRcode(m, dns.RcodeRefused)
		case 6:
			m.SetRcode(m, dns.RcodeYXDomain)
		case 7:
			m.SetRcode(m, dns.RcodeYXRrset)
		case 8:
			m.SetRcode(m, dns.RcodeNXRrset)
		case 9:
			m.SetRcode(m, dns.RcodeNotAuth)
		case 10:
			m.SetRcode(m, dns.RcodeNotZone)

		// Another cases
		default:
			m.SetRcode(m, dns.RcodeServerFailure)
		}

	} else {
		// If invalid response code is passed, set default error code (SERVFAIL)
		m.SetRcode(m, dns.RcodeServerFailure)
	}
}

// returnZeroIP - Return zero IP address for blocked domains
func returnZeroIP(m *dns.Msg, clientIP net.IP, host string) []dns.RR {

	// Return 0.0.0.0 for names in hosts.txt
	answer := dns.A{
		Hdr: dns.RR_Header{
			Name:   host,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP("0.0.0.0"),
	}
	m.Answer = append(m.Answer, &answer)
	log.Println("Zero response for:", clientIP, host)
	prom.ZeroResolutionsTotal.Inc()
	return m.Answer

}

// isAllowedQtype - Check if Qtype is allowed for DNS processing
func isAllowedQtype(qtype uint16, allowedQtypes []string) bool {
	// Convert Qtype from uint16 to string
	qtypeStr := dns.TypeToString[qtype]

	// Check if Qtype is in allowed list
	for _, allowedQtype := range allowedQtypes {
		if qtypeStr == allowedQtype {
			return true
		}
	}

	return false
}

// getQTypeResponse - Get DNS response for A or AAAA query type
func getQTypeResponse(m *dns.Msg, question dns.Question, host string, clientIP net.IP, upstreamAd string) {

	// Check if Qtype is allowed
	if isAllowedQtype(question.Qtype, config.AllowedQtypes) {
		// Possessing allowed Qtype and create answer
		if config.IsDebug {
			log.Println("Creating answer for allowed Qtype:", question.Qtype)
		}

		rAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
		if rAnswer != nil {
			if config.IsDebug {
				log.Printf("Answer: %s\n", rAnswer)
			}
			m.Answer = append(m.Answer, rAnswer...)
			prom.SuccessfulResolutionsTotal.Inc()
		} else {
			log.Println("Answer is empty set response code to (NXDOMAIN) for:", host, dns.RcodeNameError)
			setResponseCode(m, dns.RcodeNameError)
		}

	} else {
		// If IPv4 address is not available, set response code to code from MsgHdr.Rcode (resp.MsgHdr.Rcode)
		log.Println("Qtype is not allowed <num>. See allowed Qtypes in <[A AAAA ..]>:", question.Qtype, config.AllowedQtypes)
		setResponseCode(m, dns.RcodeRefused)
	}

}

// handleDNSRequest - Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, regexMap map[string]*regexp.Regexp) {

	var clientIP net.IP

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true // Set authoritative flag to compress response or not

	// Check net.IP type
	if tcpAddr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		//log.Println("TCP")
		clientIP = tcpAddr.IP
	} else if udpAddr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		//log.Println("UDP")
		clientIP = udpAddr.IP
	} else {
		log.Println("Unknown network type")
		clientIP = nil
	}

	for _, question := range r.Question {
		log.Println("Received query for:", question.Name, dns.TypeToString[question.Qtype])
		host := question.Name
		// Delete dot from the end of FQDN
		_host := strings.TrimRight(host, ".")
		matching := lists.IsMatching(_host, regexMap)
		permanentMatching := permanentHosts[_host] || (lists.IsMatching(_host, permanentRegexMap) && config.PermanentEnabled)

		//mu.Lock()
		upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
		// Check cache before requesting upstream DNS server
		if !entryInCache(m, host, question) {
			// Check if host is in hosts.txt
			// Resolve default hosts using upstream DNS for names not in hosts.txt
			if (matching && !config.Inverse) || (hosts[_host] && !config.Inverse) {
				log.Println("Resolving with default upstream server (local host):", _host, clientIP, upstreamDefault)
				getQTypeResponse(m, question, host, clientIP, upstreamDefault)
			} else if permanentMatching {
				// Get permanent upstreams
				upstreamPermanet := upstreams.GetUpstreamServer(config.DNSforWhitelisted, config.BalancingStrategy)
				log.Println("Resolving with permanent upstream server (permanent host):", _host, clientIP, upstreamPermanet)
				getQTypeResponse(m, question, host, clientIP, upstreamPermanet)
			} else {
				if matching || hosts[_host] && !permanentHosts[_host] {
					returnZeroIP(m, clientIP, host)
				} else if config.Inverse {
					//if !entryInCache(m, host, question) {
					//upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
					log.Println("Resolving with default upstream server (inverse mode):", upstreamDefault)
					getQTypeResponse(m, question, host, clientIP, upstreamDefault)
					//}
				} else {
					returnZeroIP(m, clientIP, host)
				}
			}
		} else {
			cache.CheckAndDeleteExpiredEntries()
		}
		//mu.Unlock()
	}
	defer prom.DnsQueriesTotal.Inc()
	// Send response to client and try to write response
	err := w.WriteMsg(m)
	// If error is occurred, check if it is a connection close error
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Error is related to connection close
			log.Println("Connection is closed. Skipping response.")
			return
		}
		// Other errors
		log.Printf("Error writing DNS response: %v", err)
		return
	}

}

// Inits and Main --------------------------------------------------------------- //

// InitLogging - Init logging to file and stdout
func initLogging() {
	if config.EnableLogging {
		// Create buffered output for console
		consoleOutput := bufio.NewWriter(os.Stdout)

		// Setup logger to use buffered output for console
		log.SetOutput(consoleOutput)
		log.SetFlags(log.LstdFlags | log.Lshortfile)

	} else {
		log.SetOutput(os.Stdout)
		log.Println("Logging disabled")
	}

}

// InitMetrics - Init Prometheus metrics
func initMetrics() {
	if config.MetricsEnabled {
		prometheus.MustRegister(prom.DnsQueriesTotal)
		prometheus.MustRegister(prom.SuccessfulResolutionsTotal)
		prometheus.MustRegister(prom.ZeroResolutionsTotal)
		prometheus.MustRegister(prom.ReloadHostsTotal)
		prometheus.MustRegister(prom.CacheHitResponseTotal)
	}
}

// SigtermHandler - Catch Ctrl+C or SIGTERM
func SigtermHandler(signal os.Signal) {
	if signal == syscall.SIGTERM {
		log.Println("Got kill signal. ")
		log.Println("Program will terminate now. Exit. Bye.")
		os.Exit(0)
	} else if signal == syscall.SIGINT {
		log.Println("Got CTRL+C signal. Exit. Bye.")
		os.Exit(0)
	}
}

// TEST FUNCTIONS ------------------------------------------------------------- //

// Space - Test function

// ---------------------------------------------------------------------------- //

// main - Main function. Init config, load hosts, run DNS server
func main() {

	var configFile string
	var hostsFile string
	var permanentFile string
	var wg = new(sync.WaitGroup)

	// Parse command line arguments
	addUserFlag := flag.String("adduser", "", "Username for configuration")
	delUserFlag := flag.String("deluser", "", "Username for deletion")
	forceFlag := flag.Bool("force", false, "Force operations")
	// Another flags
	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.StringVar(&hostsFile, "hosts", "hosts.txt", "Hosts file path")
	flag.StringVar(&permanentFile, "permanent", "hosts-permanent.txt", "Permanent hosts file path")
	flag.Parse()

	// Load config and pass params to vars -------------------------------------- //

	// Load config file
	if err := configuration.LoadConfig(configFile, &config); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	// User operations ---------------------------------------------------------- //

	// Add users if -adduser argument is passed
	if *addUserFlag != "" && *delUserFlag == "" {
		users.SetConfig(&config)
		users.GenerateUserConfig(*addUserFlag, *forceFlag)
	}

	// Delete users if -deluser argument is passed
	if *delUserFlag != "" && *addUserFlag == "" {
		users.SetConfig(&config)
		users.DeleteTargetUser(*delUserFlag, *forceFlag)
	}

	// Load hosts --------------------------------------------------------------- //

	// Parse hosts reload interval
	ReloadInterval, err := time.ParseDuration(config.ReloadInterval)
	if err != nil {
		log.Fatalf("Error parsing interval duration: %v", err)
	}

	// Update hosts_file parameter if -hosts argument is passed
	if hostsFile != "" {
		config.HostsFile = hostsFile
	}

	// Update permanent_whitelisted parameter if -permanent argument is passed
	if permanentFile != "" {
		config.PermanentWhitelisted = permanentFile
	}

	// Get upstream DNS servers array from config
	//upstreamServers = config.UpstreamDNSServers

	// Make init global maps vars
	mu.Lock()
	hosts = make(map[string]bool)
	permanentHosts = make(map[string]bool)
	regexMap = make(map[string]*regexp.Regexp)
	permanentRegexMap = make(map[string]*regexp.Regexp)
	mu.Unlock()

	// Init Prometheus metrics and Logging -------------------------------------- //

	// Init metrics
	initMetrics()
	// Enable logging
	initLogging()
	// Enable logging to file and stdout
	if config.EnableLogging {
		logFile, err := os.Create(config.LogFile)
		if err != nil {
			log.Fatal("Log file creation error:", err)
		}
		defer func(logFile *os.File) {
			err := logFile.Close()
			if err != nil {
				log.Printf("Error closing log file: %v", err)
				return // ignore error
			}
		}(logFile)

		// Create multiwriter for logging to file and stdout
		multiWriter := io.MultiWriter(logFile, os.Stdout)
		// Setups logger to use multiwriter
		log.SetOutput(multiWriter)
		log.Printf("Logging: Enabled. Balancing Strategy: %s. Config Version: %s. \n", config.BalancingStrategy, config.ConfigVersion)
	}

	// Load hosts with lists package -------------------------------------------- //

	// Pass config to lists package
	lists.SetConfig(&config)

	// Load hosts.txt and bind regex patterns to regexMap in to lists package
	if config.UseLocalHosts {
		lists.LoadRegexWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
		lists.LoadRegexWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)
	}
	if config.UseRemoteHosts {
		// Load hosts and regex with config interval (default 1h)
		lists.LoadHostsWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
		//lists.LoadHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, regexMap, permanentHosts)
		lists.LoadPermanentHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)
	}

	// Print more messages in to console and log for hosts files debug (after lists.LoadHosts)
	if config.IsDebug {
		fmt.Println("Hosts loaded:")
		for host := range hosts {
			fmt.Println(host)
		}
	}

	// Run DNS server ----------------------------------------------------------- //

	// Add goroutines for DNS instances running
	wg.Add(1)
	// Run DNS server for UDP requests
	go func() {
		defer wg.Done()

		udpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "udp"}
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleDNSRequest(w, r, regexMap)
		})

		log.Printf("DNS server is listening on :%d (UDP)...\n", config.DNSPort)
		err := udpServer.ListenAndServe()
		if err != nil {
			log.Printf("Error starting DNS server (UDP): %s\n", err)
		}
	}()

	// Run DNS server for TCP requests
	wg.Add(1)
	go func() {
		defer wg.Done()

		tcpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "tcp"}
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleDNSRequest(w, r, regexMap)
		})

		log.Printf("DNS server is listening on :%d (TCP)...\n", config.DNSPort)
		err := tcpServer.ListenAndServe()
		if err != nil {
			log.Printf("Error starting DNS server (TCP): %s\n", err)
		}
	}()

	// Run Prometheus metrics server
	if config.MetricsEnabled {
		wg.Add(1)
		go func() {
			log.Printf("Prometheus metrics server is listening on :%d...", config.MetricsPort)
			http.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.MetricsPort), nil)
			if err != nil {
				log.Printf("Error starting Prometheus metrics server: %s\n", err)
			}
		}()
	}

	// Exit on Ctrl+C or SIGTERM ------------------------------------------------ //

	// Handle interrupt signals
	// Thx: https://www.developer.com/languages/os-signals-go/
	sigchnl := make(chan os.Signal, 1)
	signal.Notify(sigchnl)
	exitchnl := make(chan int)
	//Call the function to handle the signals
	go func() {
		for {
			s := <-sigchnl
			SigtermHandler(s)
		}
	}()
	exitcode := <-exitchnl

	// End of program ----------------------------------------------------------- //

	// Waiting for all goroutines to complete and ensure exit
	wg.Wait()
	os.Exit(exitcode)
}
