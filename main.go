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
	"strings"
	"sync"
	"syscall"
)

// Config структура для хранения параметров конфигурации
type Config struct {
	UpstreamDNSServers []string `yaml:"upstream_dns_servers"`
	HostsFile          string   `yaml:"hosts_file"`
	DefaultIPAddress   string   `yaml:"default_ip_address"`
	DNSPort            int      `yaml:"dns_port"`
	EnableLogging      bool     `yaml:"enable_logging"`
}

var config Config
var hosts map[string]bool
var mu sync.Mutex

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

func resolveBothWithUpstream(host string, clientIP net.IP) (net.IP, net.IP) {
	client := dns.Client{}

	var ipv4, ipv6 net.IP

	// Iterate over upstream DNS servers
	for _, upstreamAddr := range config.UpstreamDNSServers {
		// Resolve IPv4
		msgIPv4 := &dns.Msg{}
		msgIPv4.SetQuestion(dns.Fqdn(host), dns.TypeA)
		log.Println("Resolving with upstream DNS for IPv4:", upstreamAddr, clientIP, host)

		respIPv4, _, err := client.Exchange(msgIPv4, upstreamAddr)
		if err == nil && len(respIPv4.Answer) > 0 {
			if a, ok := respIPv4.Answer[0].(*dns.A); ok {
				ipv4 = a.A
				break
			}
		}

		// Resolve IPv6
		msgIPv6 := &dns.Msg{}
		msgIPv6.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		log.Println("Resolving with upstream DNS for IPv6:", upstreamAddr, clientIP, host)

		respIPv6, _, err := client.Exchange(msgIPv6, upstreamAddr)
		if err == nil && len(respIPv6.Answer) > 0 {
			if aaaa, ok := respIPv6.Answer[0].(*dns.AAAA); ok {
				ipv6 = aaaa.AAAA
				break
			}
		}
	}

	// Check if there is a valid AAAA response
	if ipv6 != nil && !ipv6.Equal(net.ParseIP("::ffff:0.0.0.0")) {
		return ipv4, ipv6
	}

	// Return the default IP addresses if no successful response is obtained
	if ipv4 == nil {
		ipv4 = net.ParseIP(config.DefaultIPAddress)
	}
	if ipv6 == nil {
		ipv6 = net.ParseIP(config.DefaultIPAddress)
	}

	// Вернуть nil для ipv6, если AAAA запись отсутствует
	if ipv6.Equal(net.ParseIP("::ffff:0.0.0.0")) {
		ipv6 = nil
	}

	if ipv4 != nil && !ipv6.Equal(net.ParseIP("::ffff:0.0.0.0")) {
		// Домен имеет запись A (IPv4), но не имеет записи AAAA (IPv6)
		log.Printf("Domain %s has A address %s\n", host, ipv4.String())
	} else {
		// Домен либо не имеет записи A (IPv4), либо имеет запись AAAA (IPv6)
		log.Printf("Domain %s does not have AAAA address\n", host)
	}

	return ipv4, ipv6
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	clientIP := w.RemoteAddr().(*net.UDPAddr).IP

	for _, question := range r.Question {
		host := question.Name
		// Убрать точку с конца FQDN
		_host := strings.TrimRight(host, ".")

		mu.Lock()
		if hosts[_host] {
			// Resolve using upstream DNS for names not in hosts.txt
			//log.Println("Resolving with upstream DNS for:", clientIP, _host)
			ipv4, ipv6 := resolveBothWithUpstream(host, clientIP)

			// IPv4
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

			// IPv6
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
			}

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

func main() {
	var configFile string
	var wg = new(sync.WaitGroup)

	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

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
		log.Println("Logging enabled")
	} else {
		log.Println("Logging disabled")
	}

	if err := loadHosts(config.HostsFile); err != nil {
		log.Fatalf("Error loading hosts file: %v", err)
	}

	// Запуск сервера для обработки DNS-запросов по UDP
	wg.Add(2)

	go func() {
		defer wg.Done()

		udpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "udp"}
		dns.HandleFunc(".", handleDNSRequest)

		log.Printf("DNS server is listening on :%d (UDP)...\n", config.DNSPort)
		err := udpServer.ListenAndServe()
		if err != nil {
			log.Printf("Error starting DNS server (UDP): %s\n", err)
		}
	}()

	// Запуск сервера для обработки DNS-запросов по TCP
	//wg.Add(1)
	go func() {
		defer wg.Done()

		tcpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "tcp"}
		dns.HandleFunc(".", handleDNSRequest)

		log.Printf("DNS server is listening on :%d (TCP)...\n", config.DNSPort)
		err := tcpServer.ListenAndServe()
		if err != nil {
			log.Printf("Error starting DNS server (TCP): %s\n", err)
		}
	}()

	sigchnl := make(chan os.Signal, 1)
	signal.Notify(sigchnl)
	exitchnl := make(chan int)

	// Handle interrupt signals
	// Thx: https://www.developer.com/languages/os-signals-go/
	go func() {
		for {
			s := <-sigchnl
			SigtermHandler(s)
		}
	}()

	exitcode := <-exitchnl
	os.Exit(exitcode)

	// Ожидание завершения всех горутин
	wg.Wait()

}
