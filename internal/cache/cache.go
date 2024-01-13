// cache.go
package cache

import (
	"net"
	"sync"
	"time"
)

// CacheEntry cache entries structure
type CacheEntry struct {
	IPv4         net.IP
	IPv6         net.IP
	CreationTime time.Time
	TTL          time.Duration
}

// Cache structure for storing cache entries
type Cache struct {
	mu    sync.RWMutex
	Store map[string]CacheEntry
}

// GlobalCache global cache instance
var GlobalCache = Cache{
	Store: make(map[string]CacheEntry),
}

// RLock mutex lock
func (cache *Cache) RLock() {
	cache.mu.RLock()
}

// RUnlock mutex unlock
func (cache *Cache) RUnlock() {
	cache.mu.RUnlock()
}

// UpdateCreationTimeWithTTL update cache entry TTL and creation time
func (entry *CacheEntry) UpdateCreationTimeWithTTL(ttl time.Duration) {
	entry.CreationTime = time.Now()
	entry.TTL = ttl
}

// CheckAndDeleteExpiredEntries check and delete expired TTL entries from cache
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
