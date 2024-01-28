package cache

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"sync"
	"time"
)

// CacheEntry - Cache entries structure
type CacheEntry struct {
	IPv4         []net.IP      // IPv4 addresses from A records
	IPv6         []net.IP      // IPv6 addresses from AAAA records
	CreationTime time.Time     // Creation time
	TTL          time.Duration // Store till to this time
	DnsMsg       *dns.Msg      // DNS message (Answer)
}

// Cache - Structure for storing cache entries
type Cache struct {
	stop  chan struct{}
	mu    sync.RWMutex
	Store map[string]*CacheEntry
}

// GlobalCache - Global cache instance
var GlobalCache = Cache{
	Store: make(map[string]*CacheEntry),
}

// RLock - Mutex lock
func (cache *Cache) RLock() {
	cache.mu.RLock()
}

// RUnlock - Mutex unlock
func (cache *Cache) RUnlock() {
	cache.mu.RUnlock()
}

// Lock - Mutex lock
func (cache *Cache) Lock() {
	cache.mu.Lock()
}

// Unlock - Mutex unlock
func (cache *Cache) Unlock() {
	cache.mu.Unlock()
}

// UpdateCreationTimeWithTTL - Update cache entry TTL and creation time
func (entry *CacheEntry) UpdateCreationTimeWithTTL(ttl time.Duration) {
	entry.CreationTime = time.Now()
	entry.TTL = ttl
}

// GenerateCacheKey - Generate a unique cache key based on domain and record type
func GenerateCacheKey(domain string, recordType uint16) string {
	return fmt.Sprintf("%s_%d", domain, recordType)
}

// Caching for QTypes

// CheckCache - Check if an entry exists in the cache
func CheckCache(key string) (*CacheEntry, bool) {
	//GlobalCache.RLock()
	GlobalCache.mu.RLock()
	defer GlobalCache.mu.RUnlock()
	//key := GenerateCacheKey(domain, recordType)
	entry, ok := GlobalCache.Store[key]
	if !ok {
		return nil, false
	}
	return entry, ok
}

func WriteToCache(key string, entry *CacheEntry) {
	// Lock for write
	GlobalCache.mu.Lock()
	defer GlobalCache.mu.Unlock()

	// Write entry to cache
	GlobalCache.Store[key] = entry

	// Check and delete expired TTL entries from cache
	//CheckAndDeleteExpiredEntries()
}
