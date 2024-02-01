package maps

import (
	"log"
	"regexp"
	"sync"
)

type PermanentHostsMap struct {
	sync.Mutex
	Hosts map[string]bool
}

type PermanentHostsRegexMap struct {
	sync.Mutex
	HostsRegex map[string]*regexp.Regexp
}

// Map maker -------------------------------------------------------------- //

// NewPermanentHostsMap - create new hostsMap
func NewPermanentHostsMap() *PermanentHostsMap {
	return &PermanentHostsMap{
		Hosts: make(map[string]bool),
	}
}

// NewPermanentHostsRegexMap - create new hostsRegexMap
func NewPermanentHostsRegexMap() *PermanentHostsRegexMap {
	return &PermanentHostsRegexMap{
		HostsRegex: make(map[string]*regexp.Regexp),
	}
}

// Boolean operations ------------------------------------------------------ //

// Get - return value for key
func (hm *PermanentHostsMap) Get(key string) bool {
	hm.Lock()
	defer hm.Unlock()
	return hm.Hosts[key]
}

// Set - set value for key
func (hm *PermanentHostsMap) Set(key string, value bool) {
	hm.Lock()
	defer hm.Unlock()
	hm.Hosts[key] = value
}

// Index operations -------------------------------------------------------- //

// GetIndex - return value for key
func (hm *PermanentHostsMap) GetIndex(key string) bool {
	hm.Lock()
	defer hm.Unlock()
	return hm.Hosts[key]
}

// GetRegexIndex - return value for key
func (hrm *PermanentHostsRegexMap) GetRegexIndex(key string) *regexp.Regexp {
	hrm.Lock()
	defer hrm.Unlock()
	return hrm.HostsRegex[key]
}

// CheckIsRegexExist - check is regex exist
func (hrm *PermanentHostsRegexMap) CheckIsRegexExist(host string) bool {
	hrm.Lock()
	defer hrm.Unlock()
	for pattern, regex := range hrm.HostsRegex {
		if regex.MatchString(host) {
			log.Println("Permanent host matches regex pattern:", host, pattern)
			return true
		}
	}
	return false
}

// Regex operations ------------------------------------------------------ //

// Get - return value for key
func (hrm *PermanentHostsRegexMap) Get(key string) *regexp.Regexp {
	hrm.Lock()
	defer hrm.Unlock()
	return hrm.HostsRegex[key]
}

// Set - set value for key
func (hrm *PermanentHostsRegexMap) Set(key string, value *regexp.Regexp) {
	hrm.Lock()
	defer hrm.Unlock()
	hrm.HostsRegex[key] = value
}
