# zBLD

Zero-Trust Background Listener DNS Daemon.

![zBLD as BlackHole Server](./docs/zbld_logo.png)

Allow only specific domains from `hosts.txt` to be resolved, 
all other domains will be resolved to `0.0.0.0` as default.

## Usage Scenario

- You have a lot of servers and you want to allow only specific domains to be resolved.
- You want to block ads and malware domains on your network.
- zbld can be used as `blackhole` or `abusehole` DNS server.

## Features

- Whitelisted domains from `hosts.txt` will be resolved to real IP address.
- All other domains will be resolved to configured IP address in `config.yml`.
- Configurable upstream DNS servers (`server:port`).
- Load balancing strategies between upstream DNS servers: `robin`, `strict`.
- IPv4, IPv6 support.
- Configurable DNS port.
- Enable logging optionally.
- Regex support for specified domains in `hosts.txt`.
- zbld as inverse server (mark `hosts.txt` as block list with `inverse` option).
- Enable Prometheus metrics
- Custom port for Prometheus metrics server
- Enable Caching
- Cache DNS responses for specified TTL
- Run zbld as a service with different config and hosts files
- Load lists from URLs
- Enable / Disable loads local and remote hosts files
- Regex support for specified domains in `hosts.txt` and `hosts_url`
- Permanent whitelist with different permanent DNS servers list
- Enable logging to file
- Configurable log file name
<!-- - Detecting DNS queries type: `A`, `AAAA`, `CNAME`, `TXT`, `MX`, `NS`, `PTR`, `SRV`, `SOA`, `CAA`, `ANY`. -->

> [!CAUTION]
> If `inverse` option is enabled (see below), then zbld will converted from zero trust server to blacklist server, where `hosts.txt` and host URLs
> is a list of blocked domains.

## Usage

Build:
```shell
go build -o zbld -v .
```

Run:
```shell
./zbld
```

Try to whitelisted resolve `google.com`:
```shell
dig A google.com @127.0.0.1 -p 5001
```

Try another domain:
```shell
dig A facebook.com @127.0.0.1 -p 5001
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
log_store_duration: 1d
log_dir: "users/logs"
log_file: "zbld_root"
inverse: false
cache_enabled: true
cache_ttl_seconds: 3600
metrics_enabled: true
metrics_port: 4001
config_version: "0.1.5"
is_debug: false
```

## Prometheus Metrics

zbld exposes Prometheus metrics on `/metrics` endpoint on defined port in `metrics_port` config option.

## Permanent option
If permanent mode is enabled, then domains from `hosts-permanent.txt` will be resolved to real IP address from `permanent_dns_servers`.

> [!NOTE]  
> Permanent lists and URLs will always be whitelisted and resolved to real IP address from `permanent_dns_servers`.

## Inverse Option
This option convert zbld from zero trust server to blacklist server, where `hosts.txt` and host URLs 
is a list of blocked domains.

> [!IMPORTANT]
> Allowed permanent lists has priority over blocked

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
console_message_enable: true
console_message: "- Domain blocked by zbld. Client IP:"
```

> [!TIP]
> Permanent option is autonomous function with ignored `inverse` option. 
Domains from `hosts-permanent.txt` will always be resolved to real IP address from `permanent_dns_servers`.

* Console message will be displayed in `dig` or `nslookup` as TXT in console if `console_message_enable` is `true`.

## Specified config file

You can setup individual settings for different users, example:

```text
⋊> ~/S/zbld on dev  tree users/                                                                                                          9045 ms  dev 
users/
├── logs
│   └── user1.log
├── user1
│   ├── config.yml
│   ├── hosts-permanent.txt
│   └── hosts.txt
└── user2
    ├── config.yml
    ├── hosts-permanent.txt
    └── hosts.txt
```

> [!WARNING]  
> Then setup individual settings (like as ports or metrics) in config file for each user, then run `zbld` with `-config`,
> `-hosts`, `-permanent` options, for user1:

```shell
./zbld -config=users/user1/config.yml -hosts=users/user1/hosts.txt -permanent=users/user1/hosts-permanent.txt
```
for user2:
```shell
./zbld -config=users/user2/config.yml -hosts=users/user2/hosts.txt -permanent=users/user2/hosts-permanent.txt
```

## Users Manager

Allow add, remove, search users.

Add user:
```shell
./zbld -adduser=user_<user_id>
```

Search user:
```shell
./zbld -searchuser=<user_id>
```

Remove user:
```shell
./zbld -deluser=<user_id>
```