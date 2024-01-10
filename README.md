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
```shell
upstream_dns_servers:
  - "1.1.1.1:53"
  - "8.8.8.8:53"
# Load balancing strategies robin, strict. Default is robin
load_balancing_strategy: "robin"
hosts_file: "hosts.txt"
default_ip_address: "0.0.0.0"
dns_port: 5002
enable_logging: true
log_file: "user1-zdns.log"
inverse: true
cache_enabled: true
cache_ttl_seconds: 3600
metrics_enabled: true
metrics_port: 4002
config_version: "0.1.4"
```
