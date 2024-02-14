package main

import (
	"bufio"
	"encoding/json"
	"errors"
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
	"strings"
	"sync"
	"syscall"
	"time"
	"zbld/internal/cache"
	"zbld/internal/config"
	"zbld/internal/counter"
	"zbld/internal/fs"
	"zbld/internal/global"
	"zbld/internal/lists"
	"zbld/internal/maps"
	"zbld/internal/prometheus"
	"zbld/internal/queries"
	"zbld/internal/upstreams"
	"zbld/internal/usermgmt"
)

// Global Variables ----------------------------------------------------------- //
var config configuration.Config
var hosts *maps.HostsMap
var permanentHosts *maps.PermanentHostsMap
var hostsRegexMap *maps.HostsRegexMap
var permanentRegexMap *maps.PermanentHostsRegexMap
var counterMap *counter.CounterMap
var mu sync.Mutex

//var upstreamServers []string

// Process DNS queries ------------------------------------------------------- //

// handleCacheHit - Handle cache hit
func entryInCache(m *dns.Msg, host string, question dns.Question) (bool, []dns.RR) {

	key := cache.GenerateCacheKey(host, question.Qtype)
	entry, ok := cache.CheckCache(key)
	if ok {
		switch config.IsDebug {
		case true:
			log.Println("Cache hit answer for:", host+"\n", entry.DnsMsg.Answer)
		default:
			log.Println("Cache hit answer for:", host, entry.IPv4, entry.IPv6)
		}

		for _, rr := range entry.DnsMsg.Ns {
			if soaRecord, ok := rr.(*dns.SOA); ok {
				// Это запись типа SOA
				log.Println("Cache hit answer has AUTHORITY SECTION:", soaRecord)
				m.Ns = append(m.Ns, soaRecord)
			}
		}

		m.Answer = append(m.Answer, entry.DnsMsg.Answer...)
		if counterMap.Get(host) <= config.PromTopNameIncAfter {
			//log.Println("Host count index:", counterMap.Get(host))
			counterMap.Inc(host)
		} else {
			prom.IncrementRequestedDomainNameCounter(host)
		}

		if time.Since(entry.CreationTime) > entry.TTL {
			log.Println("Entry is expired. Deleting from cache:", key)
			cache.Del(key)
			counterMap.Del(host)
		}

		prom.IncrementCacheTotal()
		return true, m.Answer
	}

	return false, nil
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
		A: net.ParseIP(config.DefaultIPAddress),
	}
	m.Answer = append(m.Answer, &answer)
	if config.ConsoleMessageEnable {
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   m.Question[0].Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    0},
			Txt: []string{host + " " + config.ConsoleMessage + " " + clientIP.String()},
			// Another TXT fields
		})
	}
	//m.SetRcode(m, dns.RcodeNameError)
	log.Println("Zero response for:", clientIP, host)
	prom.IncrementZeroResolutionsTotal()
	prom.IncrementBlockedDomainNameCounter(host)
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

// Determine function that takes a pointer to dns.Msg
func sendResponse(w dns.ResponseWriter, response *dns.Msg) {

	if global.IsFromTCP {
		response.Compress = true
		_, err := response.Pack()
		if err != nil {
			return
		}
		global.IsFromTCP = false
	}

	err := w.WriteMsg(response)
	// If error is occurred, check if it is a connection close error
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			// Error is related to connection close
			log.Println("Connection is closed. Skipping response.")
			return
		}
		// Other errors
		log.Printf("Error writing DNS response: %v", err)
		return
	}
}

// getQTypeResponse - Get DNS response for A or AAAA query type
func getQTypeResponse(m *dns.Msg, question dns.Question, host string, clientTCP bool, upstreamAd string) {

	// Check if Qtype is allowed
	if isAllowedQtype(question.Qtype, config.AllowedQtypes) {
		// Possessing allowed Qtype and create answer
		if config.IsDebug {
			log.Println("Creating answer for allowed Qtype:", question.Qtype)
		}

		rAnswer, isAnswerExist, _ := queries.GetQTypeAnswer(host, question, upstreamAd, clientTCP)
		if rAnswer != nil {
			if config.IsDebug {
				log.Printf("Answer: %s\n", rAnswer)
			}

			if isAnswerExist {
				m.Answer = append(m.Answer, rAnswer...)
			} else {
				for _, rr := range rAnswer {
					if soaRecord, ok := rr.(*dns.SOA); ok {
						// Это запись типа SOA
						m.Ns = append(m.Ns, soaRecord)
					}
				}
			}

			prom.IncrementSuccessfulResolutionsTotal()
		} else {
			log.Println("Answer is empty set response code to (NXDOMAIN) for:", host, dns.RcodeNameError)
			prom.IncrementNXDomainNameCounter(question.Name)
			setResponseCode(m, dns.RcodeNameError)
		}

	} else {
		// If IPv4 address is not available, set response code to code from MsgHdr.Rcode (resp.MsgHdr.Rcode)
		log.Println("Qtype is not allowed <num>. See allowed Qtypes in <[A AAAA ..]>:", question.Qtype, config.AllowedQtypes)
		setResponseCode(m, dns.RcodeRefused)
	}

}

// handleDNSRequest - Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {

	var clientIP net.IP
	clientTCP := false
	m := new(dns.Msg)
	m.SetReply(r)
	//m.Authoritative = false // Set authoritative flag to compress response or not
	// Set EDNS0 options
	queries.SetEDNSOptions(m, 4096, true)

	// Get client IP address from protocol
	switch addr := w.RemoteAddr().(type) {
	case *net.TCPAddr:
		clientIP = addr.IP
		clientTCP = true
		// log.Println("TCP")
	case *net.UDPAddr:
		clientIP = addr.IP
		// log.Println("UDP")
	default:
		log.Println("Unknown network type")
		clientIP = nil
	}

	for _, question := range r.Question {
		log.Println("Received query for:", question.Name, clientIP, dns.TypeToString[question.Qtype])
		host := question.Name
		// Delete dot from the end of FQDN
		_host := strings.TrimRight(host, ".")
		//matching := lists.IsMatching(_host, hostsRegexMap)
		reMatch := hostsRegexMap.CheckIsRegexExist(_host)
		htMatch := hosts.GetIndex(_host)
		//log.Println("Matching:", matching, "Host:", hh)
		permanentMatching := permanentHosts.GetIndex(_host) || (permanentRegexMap.CheckIsRegexExist(_host) && config.PermanentEnabled)

		// Check cache before requesting upstream DNS server
		stat, _ := entryInCache(m, host, question)

		if !stat {
			upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
			// Check if host is in hosts.txt
			// Resolve default hosts using upstream DNS for names not in hosts.txt
			if (reMatch && !config.Inverse) || (htMatch && !config.Inverse) {
				log.Println("Resolving with default upstream server (local host):", _host, clientIP, upstreamDefault)
				getQTypeResponse(m, question, host, clientTCP, upstreamDefault)
			} else if permanentMatching {
				// Get permanent upstreams
				upstreamPermanet := upstreams.GetUpstreamServer(config.DNSforWhitelisted, config.BalancingStrategy)
				log.Println("Resolving with permanent upstream server (permanent host):", _host, clientIP, upstreamPermanet)
				getQTypeResponse(m, question, host, clientTCP, upstreamPermanet)
			} else {
				if reMatch || htMatch && !permanentHosts.GetIndex(_host) {
					returnZeroIP(m, clientIP, host)
				} else if config.Inverse {
					//if !entryInCache(m, host, question) {
					//upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
					log.Println("Resolving with default upstream server (inverse mode):", _host, clientIP, upstreamDefault)
					getQTypeResponse(m, question, host, clientTCP, upstreamDefault)
					//}
				} else {
					returnZeroIP(m, clientIP, host)
				}
			}
		} else if (reMatch || htMatch) && !permanentHosts.GetIndex(_host) {
			key := cache.GenerateCacheKey(host, question.Qtype)
			cache.Del(key)
		}
	}

	if config.TruncateMessages {
		if config.IsDebug {
			log.Println("Global TCP flag:", global.IsFromTCP)
		}
		if !clientTCP || !global.IsFromTCP {
			// Check if response size is more than 512 bytes
			if calculateDNSResponseSize(m) > 4096 {
				m.Truncated = true
				//global.IsFromTCP = true
			}
		}
		//global.IsFromTCP = false
	}

	sendResponse(w, m)
	prom.IncrementDnsQueriesTotal()

}

// Inits and Main --------------------------------------------------------------- //

// InitLogging - Init logging to file and stdout
func initLogging() {
	if config.EnableLogging {

		if config.EnableConsoleLogging {
			// Create buffered output for console
			consoleOutput := bufio.NewWriter(os.Stdout)
			// Setup logger to use buffered output for console
			log.SetOutput(consoleOutput)
		}

		log.SetFlags(log.LstdFlags | log.Lshortfile)

	} else {
		if config.EnableConsoleLogging {
			log.SetOutput(os.Stdout)
		} else {
			log.SetOutput(io.Discard)
		}
		log.Println("Logging disabled")
	}

}

// InitMetrics - Init Prometheus metrics
func initMetrics() {
	if config.MetricsEnabled {
		prometheus.MustRegister(prom.DnsQueriesTotal)
		prometheus.MustRegister(prom.RequestsQTypeTotal)
		prometheus.MustRegister(prom.RequestedDomainNameCounter)
		prometheus.MustRegister(prom.BlockedDomainNameCounter)
		prometheus.MustRegister(prom.NXDomainNameCounter)
		prometheus.MustRegister(prom.SuccessfulResolutionsTotal)
		prometheus.MustRegister(prom.CacheHitResponseTotal)
		prometheus.MustRegister(prom.ZeroResolutionsTotal)
		prometheus.MustRegister(prom.ReloadHostsTotal)
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

// RunCacheCleanup - Run cache cleanup routine
func RunCacheCleanup(interval time.Duration) {

	// Goroutine for periodic lists reload
	go func() {
		for {
			log.Println("Running cache cleanup routine... Interval:", interval, "seconds.")
			cache.DeleteExpiredEntries()
			time.Sleep(interval)
		}
	}()
}

// calculateDNSResponseSize - Calculate DNS response size
func calculateDNSResponseSize(response *dns.Msg) int {
	// Serialize response to bytes
	bytes, err := json.Marshal(response.Answer)
	if err != nil {
		// If error occurred during serialization
		log.Printf("Error marshalling DNS response: %v\n", err)
		return 0
	}
	// Return size of serialized response in bytes
	return len(bytes)
}

// Space - Test function
// incrementCounter - Test function for messages counting
func incrementCounter(counterName string) {
	// Вместо этого места вы можете использовать вашу библиотеку метрик.
	if config.IsDebug {
		log.Println("Incrementing counter:", counterName)
	}
}

// Funcion for processing tasks in goroutine pool.
// Tasks are taken from tasks channel.
// When the channel is closed, the goroutine stops working.
// worker - Test function for messages counting
func worker(tasks <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for task := range tasks {
		incrementCounter(task)
	}
}

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
	searchUserAliasFlag := flag.String("searchuser", "", "Search user alias")
	forceFlag := flag.Bool("force", false, "Force operations")
	clearLogsFlag := flag.Bool("clearlogs", false, "Clear logs")
	listUsersFlag := flag.Bool("listusers", false, "List existing users")
	summaryFlag := flag.Bool("summary", false, "Show summary user info")
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

	if *listUsersFlag {
		users.SetConfig(&config)
		users.ListUsers(config.UsersDir, *summaryFlag)
	}

	// Clear logs if -clearlogs argument is passed
	if *clearLogsFlag {
		maxAgeDuration, err := time.ParseDuration(config.LogStoreDuration)
		if err != nil {
			log.Fatal("Error parsing max age duration:", err)
		}
		fs.DeleteOldLogFiles(config.LogDir, maxAgeDuration)
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

	// Search user alias if -searchuser argument is passed
	if *searchUserAliasFlag != "" {
		users.SetConfig(&config)
		c, err := users.FindConfigFilesWithAlias(config.UsersDir, *searchUserAliasFlag)
		if err != nil {
			log.Fatal("Error searching user alias:", err)
		}
		// If alias found - Exit
		if len(c) > 0 {
			for _, configFile := range c {
				fmt.Println(configFile)
			}
			os.Exit(0)
		} else {
			fmt.Println("Alias not found")
			os.Exit(1)
		}
	}

	// Make init global maps vars
	mu.Lock()
	hosts = maps.NewHostsMap()
	permanentHosts = maps.NewPermanentHostsMap()
	hostsRegexMap = maps.NewHostsRegexMap()
	permanentRegexMap = maps.NewPermanentHostsRegexMap()
	cache.GlobalCache.Store = make(map[string]*cache.CacheEntry)
	counterMap = counter.NewCounterMap()
	prom.CounterChannel = make(chan string, 1000)
	mu.Unlock()

	// Init Prometheus metrics and Logging -------------------------------------- //
	initMetrics()
	initLogging()
	// Enable logging to file and stdout
	if config.EnableLogging {
		if !fs.IsDirExists(config.LogDir) {
			fs.GenerateDirs(config.LogDir)
		}
		logPath := config.LogDir + "/" + config.LogFile
		// logFile, err := os.Create(config.LogFile) // Recreate it every zbld restart
		logFile, err := os.OpenFile(logPath+"_"+time.Now().Format("2006-01-02")+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
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

		multiWriter := io.Writer(logFile)
		if config.EnableConsoleLogging {
			// Create multiwriter for logging to file and stdout
			multiWriter = io.MultiWriter(logFile, os.Stdout)
		}
		// Setups logger to use multiwriter
		log.SetOutput(multiWriter)
		log.Printf("Logging: Enabled. Balancing Strategy: %s. Config Version: %s. \n", config.BalancingStrategy, config.ConfigVersion)
	}

	// Load hosts with lists package -------------------------------------------- //

	// Pass config to lists package
	lists.SetConfig(&config)
	queries.SetConfig(&config)
	upstreams.SetConfig(&config)

	lists.LoadHostsWithInterval(config.HostsFile, ReloadInterval, hostsRegexMap, hosts)
	lists.LoadPermanentHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)

	// Run CounterChannel goroutine
	// Define goroutine pool size.
	poolSize := 10
	wg.Add(poolSize)
	// Create goroutine pool.
	for i := 0; i < poolSize; i++ {
		go worker(prom.CounterChannel, wg)
	}

	// Run DNS server ----------------------------------------------------------- //

	// Add goroutines for DNS instances running
	wg.Add(1)
	// Run DNS server for UDP requests
	go func() {
		defer wg.Done()

		udpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "udp"}
		dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
			handleDNSRequest(w, r)
		})

		log.Printf("DNS server is listening on :%d (UDP)...\n", config.DNSPort)
		err := udpServer.ListenAndServe()
		if err != nil {
			log.Printf("Error starting DNS server (UDP): %s\n", err)
		}
	}()

	if config.EnableDNSTcp {
		// Run DNS server for TCP requests
		wg.Add(1)
		go func() {
			defer wg.Done()

			tcpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "tcp"}
			dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
				handleDNSRequest(w, r)
			})

			log.Printf("DNS server is listening on :%d (TCP)...\n", config.DNSPort)
			err := tcpServer.ListenAndServe()
			if err != nil {
				log.Printf("Error starting DNS server (TCP): %s\n", err)
			}
		}()
	}

	// Run Prometheus metrics server
	if config.MetricsEnabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Printf("Prometheus metrics server is listening on :%d...", config.MetricsPort)
			http.Handle("/metrics", promhttp.Handler())
			err := http.ListenAndServe(fmt.Sprintf(":%d", config.MetricsPort), nil)
			if err != nil {
				log.Printf("Error starting Prometheus metrics server: %s\n", err)
			}
		}()
	}

	// Run log files cleanup
	if config.EnableLogging {
		wg.Add(1)
		// Go routine for creating new log file daily
		go func() {
			defer wg.Done()
			fs.CreateNewLogFileDaily(config.LogDir + "/" + config.LogFile)
		}()
	}

	// Run cache cleanup routine
	//wg.Add(1)
	//go func() {
	//	defer wg.Done()
	//	log.Println("Running cache cleanup routine...")
	//	cache.DeleteExpiredEntries()
	//	time.Sleep(time.Second)
	//}()

	cleanDuration, err := time.ParseDuration(config.CacheCleanInterval)
	RunCacheCleanup(cleanDuration)

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

	// Close CounterChannel
	close(prom.CounterChannel)
	// Waiting for all goroutines to complete and ensure exit
	wg.Wait()
	os.Exit(exitcode)
}
