// cache.go
package cache

import (
	"net"
	"sync"
	"time"
)

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
	Store map[string]CacheEntry
}

// GlobalCache глобальная переменная для кэша
var GlobalCache = Cache{
	Store: make(map[string]CacheEntry),
}

func (cache *Cache) RLock() {
	cache.mu.RLock()
}

func (cache *Cache) RUnlock() {
	cache.mu.RUnlock()
}

func (entry *CacheEntry) UpdateCreationTimeWithTTL(ttl time.Duration) {
	entry.CreationTime = time.Now()
	entry.TTL = ttl
}

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
