package prom

import (
	"github.com/prometheus/client_golang/prometheus"
)

// CounterChannel - Channel for Prometheus counters
var CounterChannel chan string

// Prometheus scoping metrics
var (
	// DnsQueriesTotal Initialized Prometheus metrics for DNS queries
	DnsQueriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zbld_dns_queries_total",
			Help: "Total number of DNS queries.",
		},
	)
	// RequestsQTypeTotal Initialized Prometheus metrics for QTypes
	RequestsQTypeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zbld_requests_qtype_total",
			Help: "Total number of DNS requests by type",
		},
		[]string{"type"},
	)
	// RequestedDomainNameCounter Initialized Prometheus metrics for first request of domain
	RequestedDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zbld_domain_name_requests_total",
			Help: "Total number of DNS requests by domain",
		},
		[]string{"domain"},
	)
	// CountUpstreamServerAddress Initialized Prometheus metrics for upstream server address
	CountUpstreamServerAddress = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zbld_upstream_server_address_total",
			Help: "Total number of DNS requests by upstream server address",
		},
		[]string{"address"},
	)
	// BlockedDomainNameCounter Initialized Prometheus metrics for blocked domains (zero responses)
	BlockedDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zbld_domain_name_blocked_total",
			Help: "Total number of blocked DNS requests by domain",
		},
		[]string{"domain"},
	)
	// NXDomainNameCounter Initialized Prometheus metrics for NXDOMAINs
	NXDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zbld_domain_name_nxdomain_total",
			Help: "Total number of NXDOMAIN answers by domain",
		},
		[]string{"domain"},
	)
	// SuccessfulResolutionsTotal Initialized Prometheus metrics
	SuccessfulResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zbld_successful_resolutions_total",
			Help: "Total number of successful DNS resolutions.",
		},
	)
	// CacheHitResponseTotal Initialized Prometheus metrics
	CacheHitResponseTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zbld_cache_hit_response_total_count",
			Help: "Total number of responses from cache count.",
		},
	)
	// ZeroResolutionsTotal Initialized Prometheus metrics
	ZeroResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zbld_zero_resolutions_total",
			Help: "Total number of zeroed DNS resolutions.",
		},
	)
	// ReloadHostsTotal Initialized Prometheus metrics
	ReloadHostsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zbld_reload_hosts_total_count",
			Help: "Total number of hosts reloads count.",
		},
	)
)

// IncrementDnsQueriesTotal - Increment DnsQueriesTotal metric
func IncrementDnsQueriesTotal() {
	DnsQueriesTotal.Inc()
	CounterChannel <- "DnsQueriesTotal"
}

// IncrementRequestsQTypeTotal - Increment RequestsQTypeTotal metric
func IncrementRequestsQTypeTotal(qtype string) {
	RequestsQTypeTotal.WithLabelValues(qtype).Inc()
	CounterChannel <- qtype
}

// IncrementRequestedDomainNameCounter - Increment RequestedDomainNameCounter metric
func IncrementRequestedDomainNameCounter(domain string) {
	RequestedDomainNameCounter.WithLabelValues(domain).Inc()
	CounterChannel <- domain
}

// IncrementCountUpstreamServerAddress - Increment CountUpstreamServerAddress metric
func IncrementCountUpstreamServerAddress(address string) {
	CountUpstreamServerAddress.WithLabelValues(address).Inc()
	CounterChannel <- address
}

// IncrementBlockedDomainNameCounter - Increment BlockedDomainNameCounter metric
func IncrementBlockedDomainNameCounter(domain string) {
	BlockedDomainNameCounter.WithLabelValues(domain).Inc()
	CounterChannel <- domain
}

// IncrementNXDomainNameCounter - Increment NXDomainNameCounter metric
func IncrementNXDomainNameCounter(domain string) {
	NXDomainNameCounter.WithLabelValues(domain).Inc()
	CounterChannel <- domain
}

// IncrementSuccessfulResolutionsTotal - Increment SuccessfulResolutionsTotal metric
func IncrementSuccessfulResolutionsTotal() {
	SuccessfulResolutionsTotal.Inc()
	CounterChannel <- "SuccessfulResolutionsTotal"
}

// IncrementCacheTotal - Increment CacheHitResponseTotal metric
func IncrementCacheTotal() {
	CacheHitResponseTotal.Inc()
	CounterChannel <- "CacheHitResponseTotal"
}

// IncrementZeroResolutionsTotal - Increment ZeroResolutionsTotal metric
func IncrementZeroResolutionsTotal() {
	ZeroResolutionsTotal.Inc()
	CounterChannel <- "ZeroResolutionsTotal"
}

// IncrementReloadHostsTotal - Increment ReloadHostsTotal metric
func IncrementReloadHostsTotal() {
	ReloadHostsTotal.Inc()
	CounterChannel <- "ReloadHostsTotal"
}
