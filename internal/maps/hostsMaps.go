package maps

import (
	"log"
	"regexp"
	"sync"
)

type HostsMap struct {
	sync.RWMutex
	Hosts map[string]bool
}

type HostsRegexMap struct {
	sync.RWMutex
	HostsRegex map[string]*regexp.Regexp
}

// Map maker -------------------------------------------------------------- //

// NewHostsMap - create new hostsMap
func NewHostsMap() *HostsMap {
	return &HostsMap{
		Hosts: make(map[string]bool),
	}
}

// NewHostsRegexMap - create new hostsRegexMap
func NewHostsRegexMap() *HostsRegexMap {
	return &HostsRegexMap{
		HostsRegex: make(map[string]*regexp.Regexp),
	}
}

// Boolean operations ------------------------------------------------------ //

// Get - return value for key
func (hm *HostsMap) Get(key string) bool {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Hosts[key]
}

// Set - set value for key
func (hm *HostsMap) Set(key string, value bool) {
	hm.Lock()
	defer hm.Unlock()
	hm.Hosts[key] = value
}

// Index operations -------------------------------------------------------- //

// GetIndex - return value for key
func (hm *HostsMap) GetIndex(key string) bool {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Hosts[key]
}

// GetRegexIndex - return value for key
func (hrm *HostsRegexMap) GetRegexIndex(key string) *regexp.Regexp {
	hrm.RLock()
	defer hrm.RUnlock()
	return hrm.HostsRegex[key]
}

// CheckIsHostExist - check if host in map
func (hm *HostsMap) CheckIsHostExist(host string) bool {
	hm.RLock()
	defer hm.RUnlock()
	return hm.Hosts[host]
}

// CheckIsRegexExist - check if regex in map
func (hrm *HostsRegexMap) CheckIsRegexExist(host string) bool {
	hrm.RLock()
	defer hrm.RUnlock()
	for pattern, regex := range hrm.HostsRegex {
		if regex.MatchString(host) {
			log.Println("Blocked host matches regex pattern:", host, pattern)
			return true
		}
	}
	return false
}

// Regex operations ------------------------------------------------------ //

// Get - return value for key
func (hrm *HostsRegexMap) Get(key string) *regexp.Regexp {
	hrm.RLock()
	defer hrm.RUnlock()
	return hrm.HostsRegex[key]
}

// Set - set value for key
func (hrm *HostsRegexMap) Set(key string, value *regexp.Regexp) {
	hrm.Lock()
	defer hrm.Unlock()
	hrm.HostsRegex[key] = value
}
