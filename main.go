package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v2"
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
)

// Config structure for storing configuration parameters
type Config struct {
	UpstreamDNSServers   []string `yaml:"upstream_dns_servers"`
	HostsFile            string   `yaml:"hosts_file"`
	HostsFileURL         []string `yaml:"hosts_file_url"`
	UseLocalHosts        bool     `yaml:"use_local_hosts"`
	UseRemoteHosts       bool     `yaml:"use_remote_hosts"`
	ReloadInterval       string   `yaml:"reload_interval_duration"`
	DefaultIPAddress     string   `yaml:"default_ip_address"`
	DNSPort              int      `yaml:"dns_port"`
	EnableLogging        bool     `yaml:"enable_logging"`
	LogFile              string   `yaml:"log_file"`
	BalancingStrategy    string   `yaml:"load_balancing_strategy"`
	Inverse              bool     `yaml:"inverse"`
	CacheTTLSeconds      int      `yaml:"cache_ttl_seconds"`
	CacheEnabled         bool     `yaml:"cache_enabled"`
	MetricsEnabled       bool     `yaml:"metrics_enabled"`
	MetricsPort          int      `yaml:"metrics_port"`
	ConfigVersion        string   `yaml:"config_version"`
	IsDebug              bool     `yaml:"is_debug"`
	PermanentEnabled     bool     `yaml:"permanent_enabled"`
	PermanentWhitelisted string   `yaml:"permanent_whitelisted"`
	DNSforWhitelisted    []string `yaml:"permanent_dns_servers"`
}

// Variables
var config Config
var hosts map[string]bool
var permanentHosts map[string]bool
var regexMap map[string]*regexp.Regexp
var permanentRegexMap map[string]*regexp.Regexp
var mu sync.Mutex
var currentIndex = 0

//var upstreamServers []string

// CacheEntry структура для хранения кэшированных записей
type CacheEntry struct {
	IPv4         net.IP
	IPv6         net.IP
	CreationTime time.Time
	TTL          time.Duration
}

// Cache структура для хранения кэша
type Cache struct {
	mu    sync.RWMutex
	store map[string]CacheEntry
}

// GlobalCache глобальная переменная для кэша
var GlobalCache = Cache{
	store: make(map[string]CacheEntry),
}

// Update cache entry creation time with TTL
func (entry *CacheEntry) updateCreationTimeWithTTL(ttl time.Duration) {
	entry.CreationTime = time.Now()
	entry.TTL = ttl
}

// Prometheus metrics
var (
	dnsQueriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_dns_queries_total",
			Help: "Total number of DNS queries.",
		},
	)
	successfulResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_successful_resolutions_total",
			Help: "Total number of successful DNS resolutions.",
		},
	)
	zeroResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_zero_resolutions_total",
			Help: "Total number of zeroed DNS resolutions.",
		},
	)
	cacheHitTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_cache_hit_total",
			Help: "Total number of cached DNS names.",
		},
	)
	reloadHostsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_reload_hosts_total_count",
			Help: "Total number of hosts reloads count.",
		},
	)
)

// Load config from file
func loadConfig(filename string) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(file, &config)
	if err != nil {
		return err
	}

	return nil
}

// Load hosts from file (domain rules)
func loadHosts(filename string, useRemote bool, urls []string, targetMap map[string]bool) error {

	var downloadedFile = "downloaded_" + filename

	if config.UseLocalHosts {
		log.Printf("Loading local hosts from %s\n", filename)
		// Загрузка локальных файлов
		//for _, filename := range filenames {
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		defer func(file *os.File) {
			err := file.Close()
			if err != nil {
				log.Printf("Error closing file: %v", err)
				return // ignore error
			}
		}(file)

		mu.Lock()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			host := strings.ToLower(scanner.Text())
			targetMap[host] = true
		}
		mu.Unlock()

		if err := scanner.Err(); err != nil {
			return err
		}
		//}
	}

	// Download remote host files
	if useRemote && !strings.Contains(filename, "permanent") {
		// Проверить, существует ли файл
		if _, err := os.Stat(downloadedFile); err == nil {
			// Если файл существует, очистить его содержимое
			if err := os.WriteFile(downloadedFile, []byte{}, 0644); err != nil {
				return err
			}
		}

		for _, url := range urls {
			log.Printf("Loading remote file from %s\n", url)
			response, err := http.Get(url)
			if err != nil {
				return err
			}
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					log.Printf("Error read body: %v", err)
					return // ignore error
				}
			}(response.Body)

			// Download to file
			// Открываем файл в режиме дозаписи (или создаем, если файл не существует)
			file, err := os.OpenFile(downloadedFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer func(file *os.File) {
				err := file.Close()
				if err != nil {
					log.Printf("Error closing file: %v", err)
					return // ignore error
				}
			}(file)

			// Записать данные из тела ответа в файл
			_, err = io.Copy(file, response.Body)
			if err != nil {
				return err
			}
			//

			mu.Lock()
			scanner := bufio.NewScanner(response.Body)
			for scanner.Scan() {
				host := strings.ToLower(scanner.Text())
				targetMap[host] = true
			}
			mu.Unlock()

			if err := scanner.Err(); err != nil {
				return err
			}
		}

		if err := loadHostsAndRegex(downloadedFile, regexMap, targetMap); err != nil {
			log.Fatalf("Error loading hosts and regex file: %v", err)
		}
	}

	// End func
	return nil
}

// Load hosts and find regex from hosts.txt file
func loadHostsAndRegex(filename string, regexMap map[string]*regexp.Regexp, targetMap map[string]bool) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Printf("Error closing file: %v", err)
			return // ignore error
		}
	}(file)

	mu.Lock()
	//hosts = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := scanner.Text()

		if strings.HasPrefix(entry, "/") && strings.HasSuffix(entry, "/") {
			// Это регулярное выражение, добавим его в regexMap
			regexPattern := entry[1 : len(entry)-1]
			if config.IsDebug {
				log.Println("Regex pattern:", regexPattern)
			}
			regex, err := regexp.Compile(regexPattern)
			if err != nil {
				return err
			}
			regexMap[regexPattern] = regex
		} else {
			// Это обычный хост, добавим его в hosts
			host := strings.ToLower(entry)
			targetMap[host] = true
		}
	}
	mu.Unlock()

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

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
	currentIndex = (currentIndex + 1) % len(upstreams)
	return upstreams[currentIndex]
}

// Get upstream server and apply balancing strategy (call from DNS handler
func getUpstreamServer(upstreams []string) string {

	switch config.BalancingStrategy {
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

func checkAndDeleteExpiredEntries() {
	// Check and delete expired TTL entries from cache
	GlobalCache.mu.Lock()
	defer GlobalCache.mu.Unlock()

	for key, entry := range GlobalCache.store {
		if time.Since(entry.CreationTime) > entry.TTL {
			delete(GlobalCache.store, key)
		}
	}
}

// Resolve both IPv4 and IPv6 addresses using upstream DNS with selected balancing strategy
func resolveBothWithUpstream(host string, clientIP net.IP, upstreamAddr string) (net.IP, net.IP) {

	if config.CacheEnabled {
		//log.Println("Cache enabled")
		GlobalCache.mu.RLock()
		entry, exists := GlobalCache.store[host]
		GlobalCache.mu.RUnlock()

		if exists {
			log.Printf("Cache hit for %s\n", host)
			cacheHitTotal.Inc()
			// Check and delete expired TTL entries from cache
			defer checkAndDeleteExpiredEntries()
			return entry.IPv4, entry.IPv6
		}
	}

	// Если записи в кэше нет, то делаем запрос к upstream DNS
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

	if config.CacheEnabled {
		// Обновление кэша
		GlobalCache.mu.Lock()
		GlobalCache.store[host] = CacheEntry{IPv4: ipv4, IPv6: ipv6}
		entry := GlobalCache.store[host]
		entry.updateCreationTimeWithTTL(time.Duration(config.CacheTTLSeconds) * time.Second)
		GlobalCache.store[host] = entry
		GlobalCache.mu.Unlock()
	}

	return ipv4, ipv6
}

// Get DNS response for A or AAAA query type
func getQTypeResponse(m *dns.Msg, question dns.Question, host string, clientIP net.IP, upstreamAd string) {
	// Resolve using upstream DNS for names not in hosts.txt
	//log.Println("Resolving with upstream DNS for:", clientIP, _host)
	ipv4, ipv6 := resolveBothWithUpstream(host, clientIP, upstreamAd)

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
		successfulResolutionsTotal.Inc()
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
			successfulResolutionsTotal.Inc()
		}
	}
}

func returnZeroIP(m *dns.Msg, clientIP net.IP, host string) {

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
	zeroResolutionsTotal.Inc()

}

// Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, regexMap map[string]*regexp.Regexp) {
	// Increase the DNS queries counter
	dnsQueriesTotal.Inc()

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
		if (isMatching(_host, regexMap) && !config.Inverse) || (hosts[_host] && !config.Inverse) {
			upstreamDefault := getUpstreamServer(config.UpstreamDNSServers)
			log.Println("Upstream server:", upstreamDefault)

			log.Println("Resolving with upstream DNS from client::", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, upstreamDefault)
		} else if (permanentHosts[_host]) || isMatching(_host, permanentRegexMap) && config.PermanentEnabled {
			// Get permanent upstreams
			upstreamPermanet := getUpstreamServer(config.DNSforWhitelisted)
			log.Println("Resolving permanent host:", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, upstreamPermanet)
		} else {
			if (isMatching(_host, regexMap)) || (hosts[_host]) && !(permanentHosts[_host]) {
				returnZeroIP(m, clientIP, host)
			} else if config.Inverse {
				upstreamDefault := getUpstreamServer(config.UpstreamDNSServers)
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

// Check if host matches regex pattern
func isMatching(host string, regexMap map[string]*regexp.Regexp) bool {
	for pattern, regex := range regexMap {
		if regex.MatchString(host) {
			log.Printf("Host %s matches regex pattern %s\n", host, pattern)
			return true
		}
	}
	return false
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
		prometheus.MustRegister(dnsQueriesTotal)
		prometheus.MustRegister(successfulResolutionsTotal)
		prometheus.MustRegister(zeroResolutionsTotal)
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

func loadHostsWithInterval(filename string, interval time.Duration, targetMap map[string]bool) {

	// Горутина для периодической загрузки
	go func() {
		for {
			log.Printf("Reloading hosts or URL file... %s\n", filename)
			if err := loadHosts(filename, config.UseRemoteHosts, config.HostsFileURL, targetMap); err != nil {
				log.Fatalf("Error loading hosts file: %v", err)
			}
			reloadHostsTotal.Inc()
			time.Sleep(interval)
		}
	}()
}

func loadRegexWithInterval(filename string, interval time.Duration, regexMap map[string]*regexp.Regexp, targetMap map[string]bool) {

	// Горутина для периодической загрузки
	go func() {
		for {
			log.Printf("Loading regex %s\n", filename)
			if err := loadHostsAndRegex(filename, regexMap, targetMap); err != nil {
				log.Fatalf("Error loading hosts and regex file: %v", err)
			}
			reloadHostsTotal.Inc()
			time.Sleep(interval)
		}
	}()
}

// Main function with entry loads and points
func main() {

	var configFile string
	var hostsFile string
	var permanentFile string
	var wg = new(sync.WaitGroup)

	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.StringVar(&hostsFile, "hosts", "hosts.txt", "Hosts file path")
	flag.StringVar(&permanentFile, "permanent", "hosts-permanent.txt", "Permanent hosts file path")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

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
	loadHostsWithInterval(config.HostsFile, ReloadInterval, hosts)
	loadHostsWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentHosts)
	loadRegexWithInterval(config.PermanentWhitelisted, ReloadInterval, permanentRegexMap, permanentHosts)

	// Load hosts.txt and bind regex patterns to regexMap
	if config.UseLocalHosts {
		loadRegexWithInterval(config.HostsFile, ReloadInterval, regexMap, hosts)
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
