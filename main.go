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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
	"zdns/internal/config"
	"zdns/internal/lists"
	"zdns/internal/prometheus"
	"zdns/internal/upstreams"
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

// getQTypeResponse - Get DNS response for A or AAAA query type
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

// handleDNSRequest - Handle DNS request from client
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
type UserConfig struct {
	DNSPort       int
	MetricsPort   int
	LogFile       string
	ConfigVersion string
	UserName      string
}

// extractNumber извлекает цифры из строки и возвращает их в виде int
func extractNumber(s string) (int, error) {
	// Ищем последовательность цифр в конце строки
	lastDigitIndex := len(s)
	for i := len(s) - 1; i >= 0; i-- {
		if !isDigit(s[i]) {
			break
		}
		lastDigitIndex = i
	}

	// Извлекаем цифры и преобразуем их в int
	number, err := strconv.Atoi(s[lastDigitIndex:])
	if err != nil {
		return 0, err
	}

	return number, nil
}

// isDigit возвращает true, если символ - цифра
func isDigit(c byte) bool {
	return '0' <= c && c <= '9'
}

// updatePort обновляет порт на основе извлеченной цифры
func updateNum(basePort, number int) int {
	// Заменяем последние цифры в basePort на извлеченное число
	portStr := strconv.Itoa(basePort)
	updatedPortStr := portStr[:len(portStr)-len(strconv.Itoa(number))] + strconv.Itoa(number)
	updatedPort, _ := strconv.Atoi(updatedPortStr)
	return updatedPort
}

func applyNewConfig(newFilename string, tmpl *template.Template, newUserConfig UserConfig) {
	// Создание нового файла для записи
	file, err := os.Create(newFilename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	// Применение шаблона и запись в файл
	err = tmpl.Execute(file, newUserConfig)
	if err != nil {
		fmt.Println("Error applying template:", err)
		return
	}

	fmt.Println("Template applied and saved to", newFilename)
}

func generateUserConfig(username string) {

	// Path to template file
	templatePath := "addits/templates/user-config-template.yml"
	// New config filename
	newFilename := "new_config_" + username + ".yml"

	// Extract number from username
	number, err := extractNumber(username)
	if err != nil {
		fmt.Println("Error extracting number:", err)
		return
	}

	// Update default ports and user index
	updatedDNSPort := updateNum(50000, number)
	updateMetricsPort := updateNum(40000, number)
	updateUserIndex := updateNum(0000, number)

	// Apply new config for new user with updated data
	newUserConfig := UserConfig{
		UserName:      username,
		DNSPort:       updatedDNSPort,
		MetricsPort:   updateMetricsPort,
		LogFile:       "users/logs/user" + strconv.Itoa(updateUserIndex) + ".log",
		ConfigVersion: "user" + strconv.Itoa(updateUserIndex) + "-config",
	}

	// Read template file
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		return
	}

	// Read and parse template file
	tmpl, err := template.New(newFilename).Parse(string(templateContent))
	//log.Println(tmpl)
	if err != nil {
		fmt.Println("Error parsing template:", err)
		return
	}

	// Apply
	//applyTemplate := func(user UserConfig) {
	//	err := tmpl.Execute(os.Stdout, user)
	//	if err != nil {
	//		fmt.Println("Error applying template:", err)
	//		return
	//	}
	//	fmt.Println()
	//}

	//applyTemplate(newUserConfig)
	applyNewConfig(newFilename, tmpl, newUserConfig)

	os.Exit(0)
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
	// Another flags
	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.StringVar(&hostsFile, "hosts", "hosts.txt", "Hosts file path")
	flag.StringVar(&permanentFile, "permanent", "hosts-permanent.txt", "Permanent hosts file path")
	flag.Parse()

	if *addUserFlag != "" {
		generateUserConfig(*addUserFlag)
	}

	// Load config and pass params to vars -------------------------------------- //

	// Load config file
	if err := configuration.LoadConfig(configFile, &config); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

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
