# zDNS

Zero Trust DNS server.

Allow only specific domains from `hosts.txt` to be resolved, 
all other domains will be resolved to `0.0.0.0` as default.

## Usage Scenario

- You have a lot of servers and you want to allow only specific domains to be resolved.
- You want to block ads and malware domains on your network.
- zDNS can be used as `blackhole` or `abusehole` DNS server.

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
hosts_file: "hosts.txt"
default_ip_address: "0.0.0.0"
dns_port: 5001
enable_logging: true

```
