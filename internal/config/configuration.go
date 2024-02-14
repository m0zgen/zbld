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
	ConsoleMessage       string   `yaml:"console_message"`
	ConsoleMessageEnable bool     `yaml:"console_message_enabled"`
	DNSPort              int      `yaml:"dns_port"`
	EnableDNSTcp         bool     `yaml:"enable_dns_tcp"`
	EnableLogging        bool     `yaml:"enable_logging"`
	EnableConsoleLogging bool     `yaml:"enable_console_logging"`
	LogDir               string   `yaml:"log_dir"`
	LogFile              string   `yaml:"log_file"`
	LogStoreDuration     string   `yaml:"log_store_duration"`
	BalancingStrategy    string   `yaml:"load_balancing_strategy"`
	Inverse              bool     `yaml:"inverse"`
	CacheTTLSeconds      int      `yaml:"cache_ttl_seconds"`
	CacheEnabled         bool     `yaml:"cache_enabled"`
	CacheCleanInterval   string   `yaml:"cache_clean_duration"`
	MetricsEnabled       bool     `yaml:"metrics_enabled"`
	MetricsPort          int      `yaml:"metrics_port"`
	PromTopNameIncAfter  int      `yaml:"prom_top_name_inc_after"`
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
	UserDirPermissionFor string   `yaml:"user_dir_permission_for"`
	AllowedQtypes        []string `yaml:"allowed_qtypes"`
	TruncateMessages     bool     `yaml:"truncate_messages"`
	BootstrapDNSServers  []string `yaml:"bootstrap_dns_servers"`
	CheckAvailableDomain string   `yaml:"check_available_domain"`
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
