package counter

import (
	"fmt"
	"sync"
)

// CounterMap представляет собой карту со счетчиками
type CounterMap struct {
	sync.RWMutex
	m map[string]int
}

// NewCounterMap создает новую CounterMap
func NewCounterMap() *CounterMap {
	return &CounterMap{
		m: make(map[string]int),
	}
}

// Get возвращает значение счетчика для указанного ключа
func (cm *CounterMap) Get(key string) int {
	cm.RLock()
	defer cm.RUnlock()
	return cm.m[key]
}

// Inc увеличивает значение счетчика для указанного ключа на 1
func (cm *CounterMap) Inc(key string) {
	cm.Lock()
	defer cm.Unlock()
	cm.m[key]++
}

func main() {
	// Создаем новую CounterMap
	counterMap := NewCounterMap()

	// Пример использования: инкрементируем счетчик для ключа "example"
	counterMap.Inc("example")

	// Получаем значение счетчика для ключа "example" и выводим его
	fmt.Println("Counter for 'example':", counterMap.Get("example"))
}
