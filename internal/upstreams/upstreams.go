package upstreams

import (
	"github.com/miekg/dns"
	"log"
	"sync"
	"time"
	configuration "zbld/internal/config"
)

// Variables --------------------------------------------------------------- //

// CurrentIndex - Selected upstream server index
var CurrentIndex = 0
var lastSelectedUpstreamIndex int // Глобальная переменная для хранения индекса последнего выбранного апстрима

var bootstrapServers []string
var checkAvailableDomain string
var permanentDNS []string
var availableIntervalDuration time.Duration

// Upstream routines ------------------------------------------------------- //

// UpstreamInfo - Upstream server information
type UpstreamInfo struct {
	Available    bool          // Флаг доступности
	LastCheck    time.Time     // Время последней проверки
	Rise         int           // Количество успешных попыток перед пометкой как доступного
	ResponseTime time.Duration // Время ответа сервера
}

// UpstreamStatus - Map to store information about upstreams
type UpstreamStatus struct {
	sync.RWMutex
	Server map[string]UpstreamInfo
}

// MakeUpstreamMap - create new hostsMap
func MakeUpstreamMap() *UpstreamStatus {
	return &UpstreamStatus{
		Server: make(map[string]UpstreamInfo),
	}
}

// Config setter -------------------------------------------------------- //

// SetConfig - Accept config.Config from external package
// and set configuration parameters to local variables
func SetConfig(cfg *configuration.Config) {
	// Set local variables through cgf.Config
	bootstrapServers = cfg.BootstrapDNSServers
	checkAvailableDomain = cfg.CheckAvailableDomain
	permanentDNS = cfg.DNSforWhitelisted
	availableIntervalDuration, _ = time.ParseDuration(cfg.FirtsAvailableInterval)

	// ...
}

// Functions for internal use ---------------------------------------------- //

// checkUpstreamAvailabilityOverDNS - Check if upstream DNS server is available
func checkUpstreamAvailabilityOverDNS(upstreamAddr string, timeout time.Duration) bool {
	// Create DNS client
	client := dns.Client{Timeout: timeout}

	// Create a request to check availability
	m := new(dns.Msg)
	m.SetQuestion(checkAvailableDomain, dns.TypeA)

	// Send a request to the upstream
	_, _, err := client.Exchange(m, upstreamAddr)
	if err != nil {
		log.Printf("Error checking upstream availability: %v\n", err)
		return false
	}

	// If there is no error, the upstream is available
	return true
}

// getNextUpstreamServer - Strict upstream balancing policy
func getNextUpstreamServer(upstreams []string) string {

	// Check if first upstream server is available (seconds 1*time.Second, milliseconds 1000*time.Millisecond
	for _, upstream := range upstreams {
		if checkUpstreamAvailabilityOverDNS(upstream, 200*time.Millisecond) {
			return upstream
		}
	}

	// If upstreams not available, try to use bootstrap servers
	for _, bootstrap := range bootstrapServers {
		if checkUpstreamAvailabilityOverDNS(bootstrap, 1*time.Second) {
			return bootstrap
		}
	}

	// If none of the servers are available, return an error or a default value
	return permanentDNS[0]
}

// getRobinUpstreamServer - Round-robin upstream balancing policy
func getRobinUpstreamServer(upstreams []string) string {
	for i := 0; i < len(upstreams); i++ {
		// Get current index with round-robin
		currentIndex := (CurrentIndex + i) % len(upstreams)
		// Check if current upstream server is available
		if checkUpstreamAvailabilityOverDNS(upstreams[currentIndex], 500*time.Millisecond) {
			return upstreams[currentIndex]
		}
	}
	// If none of the upstreams are available, use bootstrap upstream
	for _, bootstrap := range bootstrapServers {
		if checkUpstreamAvailabilityOverDNS(bootstrap, 500*time.Millisecond) {
			return bootstrap
		}
	}
	// if bootstrap upstream is not available, return an error or a default value
	return permanentDNS[0]
}

// Functions for external usage ---------------------------------------------- //

// GetUpstreamServer - Get upstream server and apply balancing strategy (call from DNS handler
func GetUpstreamServer(upstreams []string, balancingPolicy string, upstreamStatus *UpstreamStatus) string {

	switch balancingPolicy {
	case "robin":
		//log.Println("Round-robin strategy")
		return getRobinUpstreamServer(upstreams)
	case "strict":
		return getNextUpstreamServer(upstreams)
	case "available-robin":
		return getAvailableUpstream(upstreamStatus)
	case "available-fastest":
		return getFastestAvailableUpstream(upstreamStatus)
	default:
		// Default strategy is robin
		//log.Println("Default strategy (robin)")
		return getRobinUpstreamServer(upstreams)
	}

}

// Upstream Routines ------------------------------------------------------- //

// MonitorUpstreams - Periodically check the availability of all upstreams
func MonitorUpstreams(upstreamStatus *UpstreamStatus) {
	previousState := make(map[string]bool)

	for {
		upstreamStatus.Lock()
		for upstream := range upstreamStatus.Server {
			startTime := time.Now() // Засекаем время перед отправкой запроса

			currentState := checkUpstreamAvailabilityOverDNS(upstream, 200*time.Millisecond)
			if currentState != previousState[upstream] {
				if currentState {
					log.Printf("Upstream %s is marked up\n", upstream)
				} else {
					log.Printf("Upstream %s is marked down\n", upstream)
				}
				previousState[upstream] = currentState
			}

			// Обновляем значение структуры UpstreamInfo
			upstreamInfo := upstreamStatus.Server[upstream]
			if currentState {
				upstreamInfo.Rise++
			} else {
				upstreamInfo.Rise = 0
			}

			// Проверяем, если счетчик Rise достиг заданного значения
			if upstreamInfo.Rise >= 1 {
				//log.Printf("Upstream %s is marked as available\n", upstream)
				upstreamInfo.Available = true
			} else {
				upstreamInfo.Available = false
			}

			// Записываем время ответа сервера
			upstreamInfo.ResponseTime = time.Since(startTime)

			// Обновляем карту
			upstreamStatus.Server[upstream] = upstreamInfo
		}
		upstreamStatus.Unlock()

		time.Sleep(availableIntervalDuration) // Интервал проверки - 5 секунд
	}
}

// SetDefaultUpstreamInfo - Set default upstream server information in to the map
func SetDefaultUpstreamInfo(upstreamStatus *UpstreamStatus, upstreams []string) {
	upstreamStatus.Lock()
	defer upstreamStatus.Unlock()

	for _, upstream := range upstreams {
		upstreamStatus.Server[upstream] = UpstreamInfo{
			Available: true,
			LastCheck: time.Now(),
		}
	}
}

// getAvailableUpstream - Get current available upstream
func getFastestAvailableUpstream(upstreamStatus *UpstreamStatus) string {

	var fastestUpstream string
	var fastestResponseTime time.Duration

	upstreamStatus.RLock()
	defer upstreamStatus.RUnlock()

	// Return first available upstream from the map
	for upstream, info := range upstreamStatus.Server {
		if info.Available && (fastestResponseTime == 0 || info.ResponseTime < fastestResponseTime) {
			fastestUpstream = upstream
			fastestResponseTime = info.ResponseTime
		}
	}

	if fastestUpstream != "" {
		return fastestUpstream
	} else {
		// If upstreams marked as not available, use bootstrap upstream
		for _, bootstrap := range bootstrapServers {
			if checkUpstreamAvailabilityOverDNS(bootstrap, 500*time.Millisecond) {
				return bootstrap
			}
		}
	}

	//return ""
	return permanentDNS[0] // Return default value
}

// getAvailableUpstream - Get current available upstream with round-robin // Объявляем переменную вне функции
func getAvailableUpstream(upstreamStatus *UpstreamStatus) string {
	upstreamStatus.RLock()
	defer upstreamStatus.RUnlock()

	// Получаем список доступных апстримов
	availableUpstreams := make([]string, 0)
	for upstream, info := range upstreamStatus.Server {
		if info.Available {
			availableUpstreams = append(availableUpstreams, upstream)
		}
	}

	// Проверяем, есть ли доступные апстримы
	if len(availableUpstreams) == 0 {
		// Если нет доступных апстримов, используем bootstrap серверы или значение по умолчанию
		for _, bootstrap := range bootstrapServers {
			if checkUpstreamAvailabilityOverDNS(bootstrap, 500*time.Millisecond) {
				return bootstrap
			}
		}
		return permanentDNS[0] // Return default value
	}

	// Инициализируем lastSelectedUpstreamIndex, если он еще не инициализирован
	if lastSelectedUpstreamIndex < 0 {
		lastSelectedUpstreamIndex = -1 // Установим -1 для выбора первого апстрима в списке
	}

	// Выбираем апстрим по round-robin
	lastSelectedUpstreamIndex = (lastSelectedUpstreamIndex + 1) % len(availableUpstreams)
	selectedUpstream := availableUpstreams[lastSelectedUpstreamIndex]

	return selectedUpstream
}
