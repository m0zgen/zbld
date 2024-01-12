# zDNS

Zero Trust DNS server.

![zDNS as BlackHole Server](./docs/zDNS_as_blackhole.gif)

Allow only specific domains from `hosts.txt` to be resolved, 
all other domains will be resolved to `0.0.0.0` as default.

## Usage Scenario

- You have a lot of servers and you want to allow only specific domains to be resolved.
- You want to block ads and malware domains on your network.
- zDNS can be used as `blackhole` or `abusehole` DNS server.

## Features

- Whitelisted domains from `hosts.txt` will be resolved to real IP address.
- All other domains will be resolved to configured IP address in `config.yml`.
- Configurable upstream DNS servers (`server:port`).
- Load balancing strategies between upstream DNS servers: `robin`, `strict`.
- IPv4, IPv6 support.
- Configurable DNS port.
- Enable logging optionally.
- Regex support for specified domains in `hosts.txt`.
- zDNS as inverse server (mark `hosts.txt` as block list with `inverse` option).
- Enable Prometheus metrics
- Custom port for Prometheus metrics server
- Enable Caching
- Cache DNS responses for specified TTL
- Run zDNS as a service with different config and hosts files
- Load lists from URLs
- Enable / Disable loads local and remote hosts files
- Regex support for specified domains in `hosts.txt` and `hosts_url`
- Permanent whitelist with different permanent DNS servers list
- Enable logging to file
- Configurable log file name
<!-- - Detecting DNS queries type: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `PTR`, `SRV`, `SOA`, `CAA`, `ANY`. -->

## Usage

Build:
```shell
go build -o zdns -v .
```

Run:
```shell
./zdns
```

Try to whitelisted resolve `google.com`:
```shell
dig A google.com @127.0.0.1 -p 5001
```

Try another domain:
```shell
dig A facebook.com @127.0.0.1 -p 5001
```

## Specified config file

```shell
go run main.go -config=users/user1-config.yml -hosts=users/user1-hosts.txt
```

## Configuration

Example:
```yaml
upstream_dns_servers:
  - "1.1.1.1:53"
  - "8.8.8.8:53"
load_balancing_strategy: "robin"
hosts_file: "hosts.txt"
use_local_hosts: true
use_remote_hosts: true
hosts_file_url:
  - "https://raw.githubusercontent.com/m0zgen/dns-hole/master/whitelist.txt"
  - "https://raw.githubusercontent.com/m0zgen/dns-hole/master/regex/common-wl.txt"
reload_interval_duration: 1h
default_ip_address: "0.0.0.0"
dns_port: 5001
enable_logging: true
log_file: "zdns.log"
inverse: false
cache_enabled: true
cache_ttl_seconds: 3600
metrics_enabled: true
metrics_port: 4001
config_version: "0.1.5"
is_debug: false
```

## Prometheus Metrics

zDNS exposes Prometheus metrics on `/metrics` endpoint on defined port in `metrics_port` config option.

## Extra options

Permanent whitelist domains from `hosts-permanent.txt` will be resolved with configured DNS servers in `permanent_dns_servers` option.

```yaml
# Extra options
permanent_enabled: true
permanent_whitelisted: "hosts-permanent.txt"
# Upstream DNS servers for permanent whitelisted domains
permanent_dns_servers:
  - "95.85.95.85:53"
  - "2.56.220.2:53"
```

**Note**

Permanent option is autonomous function and not compatible with `inverse` option. 
Domains from `hosts-permanent.txt` will always be resolved to real IP address from `permanent_dns_servers`.
