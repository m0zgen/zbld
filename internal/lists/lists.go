package lists

import (
	"bufio"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	configuration "zdns/internal/config"
	prom "zdns/internal/prometheus"
)

var mu sync.RWMutex
var useLocalHosts bool
var useRemoteHosts bool
var hostsFileURL []string
var isDebug bool

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
// and set configuration parameters to local variables
func SetConfig(cfg *configuration.Config) {
	// Используйте cfg по необходимости
	useLocalHosts = cfg.UseLocalHosts
	useRemoteHosts = cfg.UseRemoteHosts
	hostsFileURL = cfg.HostsFileURL
	isDebug = cfg.IsDebug
	// ...
}

// Regex operations ------------------------------------------------------ //

// IsMatching - Check if host is matching regex pattern
func IsMatching(host string, regexMap map[string]*regexp.Regexp) bool {
	for pattern, regex := range regexMap {
		if regex.MatchString(host) {
			log.Printf("Host %s matches regex pattern %s\n", host, pattern)
			return true
		}
	}
	return false
}

// Load operations ------------------------------------------------------- //

// loadHosts - Load hosts from file and bind maps
func loadHosts(filename string, useRemote bool, urls []string, regexMap map[string]*regexp.Regexp, targetMap map[string]bool) error {

	var downloadedFile = "downloaded_" + filename

	if useLocalHosts {
		log.Printf("Loading local hosts from %s\n", filename)

		// load local files
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
		// Check if file exists
		if _, err := os.Stat(downloadedFile); err == nil {
			// If file exists, clear its contents
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

			// Open file in append mode (or create if file does not exist)
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

			// Record data from response body to file
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

// LoadHostsAndRegex - Load hosts and regex patterns from file
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
			// Regex pattern add it to regexMap
			regexPattern := entry[1 : len(entry)-1]
			if isDebug {
				log.Println("Regex pattern:", regexPattern)
			}
			regex, err := regexp.Compile(regexPattern)
			if err != nil {
				return err
			}
			regexMap[regexPattern] = regex
		} else {
			// Regular host entry
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

// Interval Callers  ----------------------------------------------------- //

// LoadHostsWithInterval - LoadHosts with interval
func LoadHostsWithInterval(filename string, interval time.Duration, regexMap map[string]*regexp.Regexp, targetMap map[string]bool) {

	// Goroutine for periodic lists reload
	go func() {
		for {
			log.Printf("Reloading hosts or URL file... %s\n", filename)
			if err := loadHosts(filename, useRemoteHosts, hostsFileURL, regexMap, targetMap); err != nil {
				log.Fatalf("Error loading hosts file: %v", err)
			}
			prom.ReloadHostsTotal.Inc()
			time.Sleep(interval)
		}
	}()
}

// LoadRegexWithInterval - LoadHostsAndRegex with interval
func LoadRegexWithInterval(filename string, interval time.Duration, regexMap map[string]*regexp.Regexp, targetMap map[string]bool) {

	// Goroutine for periodic lists reload
	go func() {
		for {
			log.Printf("Loading regex %s\n", filename)
			if err := loadHostsAndRegex(filename, regexMap, targetMap); err != nil {
				log.Fatalf("Error loading hosts and regex file: %v", err)
			}
			prom.ReloadHostsTotal.Inc()
			time.Sleep(interval)
		}
	}()
}
