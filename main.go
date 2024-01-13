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
	"zdns/internal/upstreams"
)

// Variables
var config configuration.Config
var hosts map[string]bool
var permanentHosts map[string]bool
var regexMap map[string]*regexp.Regexp
var permanentRegexMap map[string]*regexp.Regexp
var mu sync.Mutex

//var upstreamServers []string

// Get DNS response for A or AAAA query type
func getQTypeResponse(m *dns.Msg, question dns.Question, host string, clientIP net.IP, upstreamAd string) {
	// Resolve using upstream DNS for names not in hosts.txt
	//log.Println("Resolving with upstream DNS for:", clientIP, _host)
	ipv4, ipv6 := upstreams.ResolveBothWithUpstream(host, clientIP, upstreamAd, config.CacheEnabled, config.CacheTTLSeconds)

	// IPv4
	if question.Qtype == dns.TypeA {
		answerIPv4 := dns.A{
			Hdr: dns.RR_Header{
				Name:   host,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    0,
			},
			A: ipv4,
		}
		m.Answer = append(m.Answer, &answerIPv4)
		log.Println("Answer v4:", answerIPv4)
		prom.SuccessfulResolutionsTotal.Inc()
	}

	// IPv6
	if question.Qtype == dns.TypeAAAA {
		if ipv6 != nil {
			answerIPv6 := dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   host,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				AAAA: ipv6,
			}
			m.Answer = append(m.Answer, &answerIPv6)
			log.Println("Answer v6:", answerIPv6)
			prom.SuccessfulResolutionsTotal.Inc()
		}
	}
}

// Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, regexMap map[string]*regexp.Regexp) {
	// Increase the DNS queries counter
	prom.DnsQueriesTotal.Inc()

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

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
			log.Println("Upstream server:", upstreamDefault)
			log.Println("Resolving regular host from client:", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, upstreamDefault)
		} else if (permanentHosts[_host]) || lists.IsMatching(_host, permanentRegexMap) && config.PermanentEnabled {
			// Get permanent upstreams
			upstreamPermanet := upstreams.GetUpstreamServer(config.DNSforWhitelisted, config.BalancingStrategy)
			log.Println("Resolving permanent host from client:", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, upstreamPermanet)
		} else {
			if (lists.IsMatching(_host, regexMap)) || (hosts[_host]) && !(permanentHosts[_host]) {
				upstreams.ReturnZeroIP(m, clientIP, host)
			} else if config.Inverse {
				upstreamDefault := upstreams.GetUpstreamServer(config.UpstreamDNSServers, config.BalancingStrategy)
				log.Println("Upstream server:", upstreamDefault)
				getQTypeResponse(m, question, host, clientIP, upstreamDefault)
			} else {
				upstreams.ReturnZeroIP(m, clientIP, host)
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

// Init logging
func initLogging() {
	if config.EnableLogging {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetOutput(os.Stdout)
		log.Println("Logging disabled")
	}

}

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

// Main function with entry lists and points
func main() {

	var configFile string
	var hostsFile string
	var permanentFile string
	var wg = new(sync.WaitGroup)

	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.StringVar(&hostsFile, "hosts", "hosts.txt", "Hosts file path")
	flag.StringVar(&permanentFile, "permanent", "hosts-permanent.txt", "Permanent hosts file path")
	flag.Parse()

	if err := configuration.LoadConfig(configFile, &config); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	lists.SetConfig(&config)

	// Парсинг интервала обновления hosts
	ReloadInterval, err := time.ParseDuration(config.ReloadInterval)
	if err != nil {
		log.Fatalf("Error parsing interval duration: %v", err)
	}

	// Обновить параметр hosts_file, если передан аргумент -hosts
	if hostsFile != "" {
		config.HostsFile = hostsFile
	}

	// Обновить параметр permanent_whitelisted, если передан аргумент -permanent
	if permanentFile != "" {
		config.PermanentWhitelisted = permanentFile
	}

	// Show app version on start
	var appVersion = config.ConfigVersion
	// Get upstream DNS servers array from config
	//upstreamServers = config.UpstreamDNSServers

	// Init global vars
	mu.Lock()
	hosts = make(map[string]bool)
	permanentHosts = make(map[string]bool)
	regexMap = make(map[string]*regexp.Regexp)
	permanentRegexMap = make(map[string]*regexp.Regexp)
	mu.Unlock()

	// Load hosts from file
	//if err := loadHosts(config.HostsFile, config.UseRemoteHosts, config.HostsFileURL); err != nil {
	//	log.Fatalf("Error loading hosts file: %v", err)
	//}

	// Загрузка hosts и regex с интервалом 1 час
	lists.LoadHostsWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
	lists.LoadHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, regexMap, permanentHosts)
	lists.LoadRegexWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)

	// Load hosts.txt and bind regex patterns to regexMap
	if config.UseLocalHosts {
		lists.LoadRegexWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
	}

	// Init metrics
	initMetrics()
	// Enable logging
	initLogging()

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
		// Настройка логгера для использования мультирайтера
		log.SetOutput(multiWriter)
		//log.SetOutput(logFile)
		log.Println("Logging enabled. Version:", appVersion)
	} else {
		log.Println("Logging disabled")
	}

	if config.IsDebug {
		fmt.Println("Hosts loaded:")
		for host := range hosts {
			fmt.Println(host)
		}
	}

	// Run DNS server instances with goroutine
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

	// Запуск сервера для метрик Prometheus
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

	// Waiting for all goroutines to complete
	wg.Wait()

	os.Exit(exitcode)

}
