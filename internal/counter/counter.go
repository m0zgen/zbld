package counter

import (
	"sync"
)

// CounterMap is a map with counters
type CounterMap struct {
	sync.RWMutex
	m map[string]int
}

// NewCounterMap - create new CounterMap
func NewCounterMap() *CounterMap {
	return &CounterMap{
		m: make(map[string]int),
	}
}

// Get - return counter value for key
func (cm *CounterMap) Get(key string) int {
	cm.RLock()
	defer cm.RUnlock()
	return cm.m[key]
}

// Inc - increment counter for key by 1
func (cm *CounterMap) Inc(key string) {
	cm.Lock()
	defer cm.Unlock()
	cm.m[key]++
}

// Del - delete element from map by key
func (cm *CounterMap) Del(key string) {
	cm.Lock()
	defer cm.Unlock()
	delete(cm.m, key)
}
