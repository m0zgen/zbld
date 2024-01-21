package configuration

import (
	"gopkg.in/yaml.v2"
	"os"
)

// Config structure for storing configuration parameters
type Config struct {
	UpstreamDNSServers   []string `yaml:"upstream_dns_servers"`
	HostsFile            string   `yaml:"hosts_file"`
	HostsFileURL         []string `yaml:"hosts_file_url"`
	UseLocalHosts        bool     `yaml:"use_local_hosts"`
	UseRemoteHosts       bool     `yaml:"use_remote_hosts"`
	ReloadInterval       string   `yaml:"reload_interval_duration"`
	DefaultIPAddress     string   `yaml:"default_ip_address"`
	DNSPort              int      `yaml:"dns_port"`
	EnableLogging        bool     `yaml:"enable_logging"`
	LogFile              string   `yaml:"log_file"`
	BalancingStrategy    string   `yaml:"load_balancing_strategy"`
	Inverse              bool     `yaml:"inverse"`
	CacheTTLSeconds      int      `yaml:"cache_ttl_seconds"`
	CacheEnabled         bool     `yaml:"cache_enabled"`
	MetricsEnabled       bool     `yaml:"metrics_enabled"`
	MetricsPort          int      `yaml:"metrics_port"`
	ConfigVersion        string   `yaml:"config_version"`
	IsDebug              bool     `yaml:"is_debug"`
	PermanentEnabled     bool     `yaml:"permanent_enabled"`
	PermanentWhitelisted string   `yaml:"permanent_whitelisted"`
	PermanentFileURL     []string `yaml:"permanent_file_url"`
	DNSforWhitelisted    []string `yaml:"permanent_dns_servers"`
	UserHostsTemplate    string   `yaml:"user_hosts_template"`
	UserHostsPermTmpl    string   `yaml:"user_hosts_permanent_template"`
	UserConfigTemplate   string   `yaml:"user_config_template"`
	UsersDir             string   `yaml:"users_dir"`
	UsersLogDir          string   `yaml:"users_log_dir"`
	AllowedQtypes        []string `yaml:"allowed_qtypes"`
}

// LoadConfig - Load configuration from file
func LoadConfig(filename string, cfg *Config) error {
	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(file, cfg)
	if err != nil {
		return err
	}

	return nil
}
