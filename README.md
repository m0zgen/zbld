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
dns_port: 5001
enable_logging: true

```
