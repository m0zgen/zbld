package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
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

func resolveWithUpstream(host string) net.IP {
	client := dns.Client{}

	// Iterate over upstream DNS servers
	for _, upstreamAddr := range config.UpstreamDNSServers {
		msg := &dns.Msg{}
		msg.SetQuestion(dns.Fqdn(host), dns.TypeA)

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

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, question := range r.Question {
		host := question.Name
		// Убрать точку с конца FQDN
		_host := strings.TrimRight(host, ".")

		mu.Lock()
		if hosts[_host] {
			// Resolve using upstream DNS for names not in hosts.txt
			fmt.Println("Resolving with upstream DNS for:", _host)
			ip := resolveWithUpstream(host)
			answer := dns.A{
				Hdr: dns.RR_Header{
					Name:   host,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				A: ip,
			}
			m.Answer = append(m.Answer, &answer)
		} else {
			// Return 0.0.0.0 for names in hosts.txt
			fmt.Println("Zero response for:", host)
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

func main() {
	var configFile string
	var wg sync.WaitGroup

	flag.StringVar(&configFile, "config", "config.yml", "Config file path")
	flag.Parse()

	if err := loadConfig(configFile); err != nil {
		log.Fatalf("Error loading config file: %v", err)
	}

	initLogging()

	if config.EnableLogging {
		file, err := os.Create("zdns.log")
		if err != nil {
			log.Fatal("Log file creation error:", err)
		}
		defer file.Close()

		log.SetOutput(file)
		log.Println("Logging enabled")
	} else {
		log.Println("Logging disabled")
	}

	if err := loadHosts(config.HostsFile); err != nil {
		log.Fatalf("Error loading hosts file: %v", err)
	}

	//server := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "udp"}
	//dns.HandleFunc(".", handleDNSRequest)
	//
	//fmt.Println("DNS server is listening on :", config.DNSPort)
	//err := server.ListenAndServe()
	//if err != nil {
	//	fmt.Printf("Error starting DNS server: %s\n", err)
	//}

	// Запуск сервера для обработки DNS-запросов по UDP
	//go func() {
	//	udpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "udp"}
	//	dns.HandleFunc(".", handleDNSRequest)
	//
	//	log.Printf("DNS server is listening on :%d (UDP)...\n", config.DNSPort)
	//	err := udpServer.ListenAndServe()
	//	if err != nil {
	//		log.Printf("Error starting DNS server (UDP): %s\n", err)
	//	}
	//}()

	// Запуск сервера для обработки DNS-запросов по TCP
	//go func() {
	//	tcpServer := &dns.Server{Addr: fmt.Sprintf(":%d", config.DNSPort), Net: "tcp"}
	//	dns.HandleFunc(".", handleDNSRequest)
	//
	//	log.Printf("DNS server is listening on :%d (TCP)...\n", config.DNSPort)
	//	err := tcpServer.ListenAndServe()
	//	if err != nil {
	//		log.Printf("Error starting DNS server (TCP): %s\n", err)
	//	}
	//}()

	// Ожидание сигнала завершения работы (Ctrl+C, например)
	//select {}

	// Запуск сервера для обработки DNS-запросов по UDP
	wg.Add(1)
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
	wg.Add(1)
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

	// Ожидание завершения всех горутин
	wg.Wait()

}
