package prom

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus scoping metrics
var (
	// DnsQueriesTotal Initialized Prometheus metrics
	DnsQueriesTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_dns_queries_total",
			Help: "Total number of DNS queries.",
		},
	)
	// SuccessfulResolutionsTotal Initialized Prometheus metrics
	SuccessfulResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_successful_resolutions_total",
			Help: "Total number of successful DNS resolutions.",
		},
	)
	// ZeroResolutionsTotal Initialized Prometheus metrics
	ZeroResolutionsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_zero_resolutions_total",
			Help: "Total number of zeroed DNS resolutions.",
		},
	)
	// ReloadHostsTotal Initialized Prometheus metrics
	ReloadHostsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_reload_hosts_total_count",
			Help: "Total number of hosts reloads count.",
		},
	)
	// CacheHitResponseTotal Initialized Prometheus metrics
	CacheHitResponseTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "zdns_cache_hit_response_total_count",
			Help: "Total number of responses from cache count.",
		},
	)
	RequestsQTypeTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_requests_qtype_total",
			Help: "Total number of DNS requests by type",
		},
		[]string{"type"},
	)
	RequestedDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_domain_name_requests_total",
			Help: "Total number of DNS requests by domain",
		},
		[]string{"domain"},
	)
	BlockedDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_domain_name_blocked_total",
			Help: "Total number of blocked DNS requests by domain",
		},
		[]string{"domain"},
	)
	NXDomainNameCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "zdns_domain_name_nxdomain_total",
			Help: "Total number of NXDOMAIN answers by domain",
		},
		[]string{"domain"},
	)
)
