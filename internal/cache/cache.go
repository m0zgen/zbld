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
	IPv4         []net.IP
	IPv6         []net.IP
	CreationTime time.Time
	TTL          time.Duration
	DnsMsg       *dns.Msg
}

// Cache - Structure for storing cache entries
type Cache struct {
	mu    sync.RWMutex
	Store map[string]CacheEntry
}

// GlobalCache - Global cache instance
var GlobalCache = Cache{
	Store: make(map[string]CacheEntry),
}

// RLock - Mutex lock
func (cache *Cache) RLock() {
	cache.mu.RLock()
}

// RUnlock - Mutex unlock
func (cache *Cache) RUnlock() {
	cache.mu.RUnlock()
}

// UpdateCreationTimeWithTTL - Update cache entry TTL and creation time
func (entry *CacheEntry) UpdateCreationTimeWithTTL(ttl time.Duration) {
	entry.CreationTime = time.Now()
	entry.TTL = ttl
}

// CheckAndDeleteExpiredEntries - Check and delete expired TTL entries from cache
func CheckAndDeleteExpiredEntries() {
	// Check and delete expired TTL entries from cache
	GlobalCache.mu.Lock()
	defer GlobalCache.mu.Unlock()

	for key, entry := range GlobalCache.Store {
		if time.Since(entry.CreationTime) > entry.TTL {
			delete(GlobalCache.Store, key)
		}
	}
}

// Caching for QTypes

// CheckCache - Check if an entry exists in the cache
func CheckCache(domain string, recordType uint16) (*CacheEntry, bool) {
	key := GenerateCacheKey(domain, recordType)

	GlobalCache.mu.RLock()
	defer GlobalCache.mu.RUnlock()

	entry, ok := GlobalCache.Store[key]
	return &entry, ok
}

// GenerateCacheKey - Generate a unique cache key based on domain and record type
func GenerateCacheKey(domain string, recordType uint16) string {
	return fmt.Sprintf("%s_%d", domain, recordType)
}
