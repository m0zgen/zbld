package main

import (
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

	//ipv4, ipv6, _ := upstreams.ResolveBothWithUpstream(host, clientIP, upstreamAd, config.CacheEnabled, config.CacheTTLSeconds)
	//log.Println("Caching answer for:", host, ipv4, ipv6)

	if isAllowedQtype(question.Qtype, config.AllowedQtypes) {
		// Possessing allowed Qtype and create answer
		log.Println("Creating answer for allowed Qtype:", question.Qtype)
		rAnswer, _ := queries.GetQTypeAnswer(host, question, upstreamAd)
		if rAnswer != nil {
			log.Printf("Answer: %s\n", rAnswer)
			m.Answer = append(m.Answer, rAnswer...)
			prom.SuccessfulResolutionsTotal.Inc()
		} else {
			log.Printf("Answer is empty. Setting response code to (NXDOMAIN) %d\n", dns.RcodeNameError)
			setResponseCode(m, dns.RcodeNameError)
		}

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

	} else {
		// If IPv4 address is not available, set response code to code from MsgHdr.Rcode (resp.MsgHdr.Rcode)
		log.Printf("Qtype is not allowed: %s. Allowed Qtypes: %s\n", question.Qtype, config.AllowedQtypes)
		setResponseCode(m, dns.RcodeRefused)
	}

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

}

// handleDNSRequest - Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, regexMap map[string]*regexp.Regexp) {
	// Increase the DNS queries counter
	prom.DnsQueriesTotal.Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true // Set authoritative flag to compress response or not

	var clientIP net.IP
	//var upstreamAd string

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
		log.Printf("Received query for %s type %s\n", question.Name, dns.TypeToString[question.Qtype])
		host := question.Name
		// Убрать точку с конца FQDN
		_host := strings.TrimRight(host, ".")

		mu.Lock()

		// Resolve default hosts using upstream DNS for names not in hosts.txt
		if (lists.IsMatching(_host, regexMap) && !config.Inverse) || (hosts[_host] && !config.Inverse) {
			upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
			log.Printf("Resolving local host %s from client %s. Upstream server: %s\n", _host, clientIP, upstreamDefault)
			getQTypeResponse(m, question, host, clientIP, upstreamDefault)
		} else if (permanentHosts[_host]) || lists.IsMatching(_host, permanentRegexMap) && config.PermanentEnabled {
			// Get permanent upstreams
			upstreamPermanet := upstreams.GetUpstreamServer(config.DNSforWhitelisted, config.BalancingStrategy)
			log.Printf("Resolving permanent host %s from client %s. Upstream server: %s\n", _host, clientIP, upstreamPermanet)
			getQTypeResponse(m, question, host, clientIP, upstreamPermanet)
		} else {
			if (lists.IsMatching(_host, regexMap)) || (hosts[_host]) && !(permanentHosts[_host]) {
				returnZeroIP(m, clientIP, host)
			} else if config.Inverse {
				upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
				log.Println("Upstream server:", upstreamDefault)
				getQTypeResponse(m, question, host, clientIP, upstreamDefault)
			} else {
				returnZeroIP(m, clientIP, host)
			}
		}
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
		mu.Unlock()
	}

	err := w.WriteMsg(m)
	if err != nil {
		log.Printf("Error writing DNS response: %v", err)
		return
	}
}

// Inits and Main --------------------------------------------------------------- //

// InitLogging - Init logging to file and stdout
func initLogging() {
	if config.EnableLogging {
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

	// Show app version on start
	var appVersion = config.ConfigVersion
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
		log.Println("Logging enabled. Version:", appVersion)
	} else {
		log.Println("Logging disabled")
	}

	// Load hosts with lists package -------------------------------------------- //

	// Pass config to lists package
	lists.SetConfig(&config)
	// Load hosts and regex with config interval (default 1h)
	lists.LoadHostsWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
	lists.LoadHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, regexMap, permanentHosts)
	lists.LoadRegexWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)
	// Load hosts.txt and bind regex patterns to regexMap in to lists package
	if config.UseLocalHosts {
		lists.LoadRegexWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
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
	wg.Add(2)

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
	//wg.Add(1)
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
