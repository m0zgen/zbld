package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
	"io"
	"io/ioutil"
	"log"
	"net"
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
	UpstreamDNSServers []string `yaml:"upstream_dns_servers"`
	HostsFile          string   `yaml:"hosts_file"`
	DefaultIPAddress   string   `yaml:"default_ip_address"`
	DNSPort            int      `yaml:"dns_port"`
	EnableLogging      bool     `yaml:"enable_logging"`
	BalancingStrategy  string   `yaml:"load_balancing_strategy"`
}

// Variables
var config Config
var hosts map[string]bool
var mu sync.Mutex
var currentIndex = 0
var upstreamServers []string

// Load config from file
func loadConfig(filename string) error {
	file, err := ioutil.ReadFile(filename)
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
func loadHosts(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	mu.Lock()
	hosts = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := strings.ToLower(scanner.Text())
		hosts[host] = true
	}
	mu.Unlock()

	if err := scanner.Err(); err != nil {
		return err
	}

	//fmt.Println("Hosts loaded:")
	//for host := range hosts {
	//	fmt.Println(host)
	//}

	// End func
	return nil
}

// Load hosts and find regex from hosts.txt file
func loadHostsAndRegex(filename string, regexMap map[string]*regexp.Regexp) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	mu.Lock()
	hosts = make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		entry := scanner.Text()

		if strings.HasPrefix(entry, "/") && strings.HasSuffix(entry, "/") {
			// Это регулярное выражение, добавим его в regexMap
			regexPattern := entry[1 : len(entry)-1]
			log.Println("Regex pattern:", regexPattern)
			regex, err := regexp.Compile(regexPattern)
			if err != nil {
				return err
			}
			regexMap[regexPattern] = regex
		} else {
			// Это обычный хост, добавим его в hosts
			host := strings.ToLower(entry)
			hosts[host] = true
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
	defer conn.Close()
	return true
}

// Strict upstream balancing policy
func getNextUpstreamServer() string {

	// Проверить доступность первого сервера
	if isUpstreamServerAvailable(upstreamServers[0], 2*time.Second) {
		return upstreamServers[0]
	}

	// Если первый сервер недоступен, вернуть второй
	return upstreamServers[1]
}

// Round-robin upstream balancing policy
func getRobinUpstreamServer() string {
	//mu.Lock()
	//defer mu.Unlock()
	// Простой round-robin: выбираем следующий сервер
	currentIndex = (currentIndex + 1) % len(config.UpstreamDNSServers)
	return upstreamServers[currentIndex]
}

// Get upstream server and apply balancing strategy (call from DNS handler
func getUpstreamServer() string {

	switch config.BalancingStrategy {
	case "robin":
		log.Println("Round-robin strategy")
		return getRobinUpstreamServer()
	case "strict":
		log.Println("Strict strategy")
		return getNextUpstreamServer()
	default:
		// Default strategy is robin
		log.Println("Default strategy (robin)")
		return getRobinUpstreamServer()
	}

}

// Testing function
func resolveWithUpstream(host string, clientIP net.IP) net.IP {
	client := dns.Client{}

	// Iterate over upstream DNS servers
	for _, upstreamAddr := range config.UpstreamDNSServers {
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)
		log.Println("Resolving with upstream DNS for:", upstreamAddr, clientIP, host)

		resp, _, err := client.Exchange(msg, upstreamAddr)
		if err == nil && len(resp.Answer) > 0 {
			// Return the first successful response from upstream
			if a, ok := resp.Answer[0].(*dns.A); ok {
				return a.A
			}
		}
	}

	return net.ParseIP(config.DefaultIPAddress)
}

// Resolve both IPv4 and IPv6 addresses using upstream DNS with selected balancing strategy
func resolveBothWithUpstream(host string, clientIP net.IP, upstreamAddr string) (net.IP, net.IP) {
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

	return ipv4, ipv6
}

// Get DNS response for A or AAAA query type
func getQTypeResponse(m *dns.Msg, question dns.Question, host string, clientIP net.IP, _host string, upstreamAd string) {
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
		}
	}
}

// Handle DNS request from client
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg, regexMap map[string]*regexp.Regexp) {

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

		//Call round-robin
		upstreamAd := getUpstreamServer()
		log.Println("Upstream server:", upstreamAd)

		// Resolve using upstream DNS for names not in hosts.txt
		if isMatching(_host, regexMap) {
			log.Println("Resolving with upstream DNS as RegEx:", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, _host, upstreamAd)
		} else if hosts[_host] {
			log.Println("Resolving with upstream DNS as simple line:", clientIP, _host)
			getQTypeResponse(m, question, host, clientIP, _host, upstreamAd)
		} else {
			// Return 0.0.0.0 for names in hosts.txt
			log.Println("Zero response for:", clientIP, host)
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
		}
		mu.Unlock()
	}

	w.WriteMsg(m)
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
		log.SetOutput(ioutil.Discard)
	}

}

// SigtermHandler - Catch Ctrl+C or SIGTERM
func SigtermHandler(signal os.Signal) {
	if signal == syscall.SIGTERM {
		log.Println("Got kill signal. ")
		log.Println("Program will terminate now.")
		log.Println("Got kill signal. Exit.")
		os.Exit(0)
	} else if signal == syscall.SIGINT {
		log.Println("Got CTRL+C signal")
		log.Println("Closing.")
		log.Println("Got CTRL+C signal. Exit.")
		os.Exit(0)
	}
}

// Main function with entry loads and points
func main() {
	var appVersion = "0.1.2"
	var configFile string
	var wg = new(sync.WaitGroup)

	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	// Get upstream DNS servers array from config
	upstreamServers = config.UpstreamDNSServers

	// Enable logging
	initLogging()

	if config.EnableLogging {
		logFile, err := os.Create("zdns.log")
		if err != nil {
			log.Fatal("Log file creation error:", err)
		}
		defer logFile.Close()

		// Создание мультирайтера для записи в файл и вывода на экран
		multiWriter := io.MultiWriter(logFile, os.Stdout)
		// Настройка логгера для использования мультирайтера
		log.SetOutput(multiWriter)
		//log.SetOutput(logFile)
		log.Println("Logging enabled. Version:", appVersion)
	} else {
		log.Println("Logging disabled")
	}

	// Load hosts from file
	if err := loadHosts(config.HostsFile); err != nil {
		log.Fatalf("Error loading hosts file: %v", err)
	}

	// Regex map
	regexMap := make(map[string]*regexp.Regexp)

	// Load hosts.txt and bind regex patterns to regexMap
	if err := loadHostsAndRegex(config.HostsFile, regexMap); err != nil {
		log.Fatalf("Error loading hosts and regex file: %v", err)
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
	os.Exit(exitcode)

	// Waiting for all goroutines to complete
	wg.Wait()

}
