```markdown
# Wireshark Filters Cheat Sheet

## Table of Contents
- [Basic Filter Syntax](#basic-filter-syntax)
- [Common Protocol Filters](#common-protocol-filters)
- [IP Address Filters](#ip-address-filters)
- [Port Number Filters](#port-number-filters)
- [HTTP Filters](#http-filters)
- [DNS Filters](#dns-filters)
- [TCP/UDP Filters](#tcpudp-filters)
- [Advanced Filters](#advanced-filters)
- [Display vs Capture Filters](#display-vs-capture-filters)
- [Practical Examples](#practical-examples)

## Basic Filter Syntax

| Filter | Description |
|--------|-------------|
| `protocol` | Filter by protocol (e.g., `tcp`, `udp`, `http`) |
| `==` | Equal to |
| `!=` | Not equal to |
| `&&` | Logical AND |
| `||` | Logical OR |
| `!` | Logical NOT |
| `contains` | Packet contains specified value |
| `matches` | Regular expression match |

## Common Protocol Filters

| Filter | Description |
|--------|-------------|
| `tcp` | Show only TCP packets |
| `udp` | Show only UDP packets |
| `icmp` | Show only ICMP packets |
| `http` | Show only HTTP packets |
| `dns` | Show only DNS packets |
| `ssl` | Show only SSL/TLS packets |
| `arp` | Show only ARP packets |
| `bootp` | Show only DHCP packets |
| `ftp` | Show only FTP packets |
| `ssh` | Show only SSH packets |

## IP Address Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `ip.addr` | Filter by IP address | `ip.addr == 192.168.1.1` |
| `ip.src` | Filter by source IP | `ip.src == 10.0.0.5` |
| `ip.dst` | Filter by destination IP | `ip.dst == 8.8.8.8` |
| `ip.addr !=` | Exclude IP address | `ip.addr != 192.168.1.100` |
| `ip.src_host` | Source host IP | `ip.src_host == 192.168.1.1` |
| `ip.dst_host` | Destination host IP | `ip.dst_host == 10.0.0.2` |

## Port Number Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `tcp.port` | Filter by TCP port | `tcp.port == 80` |
| `udp.port` | Filter by UDP port | `udp.port == 53` |
| `tcp.srcport` | Filter by TCP source port | `tcp.srcport == 443` |
| `tcp.dstport` | Filter by TCP destination port | `tcp.dstport == 22` |
| `udp.srcport` | Filter by UDP source port | `udp.srcport == 123` |
| `udp.dstport` | Filter by UDP destination port | `udp.dstport == 161` |

## HTTP Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `http.request` | HTTP requests only | `http.request` |
| `http.response` | HTTP responses only | `http.response` |
| `http.host` | Filter by host header | `http.host == "example.com"` |
| `http.user_agent` | Filter by user agent | `http.user_agent contains "Chrome"` |
| `http.request.method` | Filter by HTTP method | `http.request.method == "GET"` |
| `http.request.uri` | Filter by URI | `http.request.uri contains "login"` |
| `http.response.code` | Filter by status code | `http.response.code == 404` |

## DNS Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `dns` | All DNS traffic | `dns` |
| `dns.flags.response` | DNS responses only | `dns.flags.response == 1` |
| `dns.qry.name` | Filter by query name | `dns.qry.name == "google.com"` |
| `dns.resp.name` | Filter by response name | `dns.resp.name contains "microsoft"` |
| `dns.qry.type` | Filter by query type | `dns.qry.type == 1` (A record) |

## TCP/UDP Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `tcp.flags.syn` | TCP SYN packets | `tcp.flags.syn == 1` |
| `tcp.flags.ack` | TCP ACK packets | `tcp.flags.ack == 1` |
| `tcp.flags.fin` | TCP FIN packets | `tcp.flags.fin == 1` |
| `tcp.flags.reset` | TCP RST packets | `tcp.flags.reset == 1` |
| `tcp.analysis.retransmission` | TCP retransmissions | `tcp.analysis.retransmission` |
| `tcp.analysis.zero_window` | TCP zero window | `tcp.analysis.zero_window` |
| `tcp.window_size` | Filter by window size | `tcp.window_size < 1000` |

## Advanced Filters

| Filter | Description | Example |
|--------|-------------|---------|
| `frame.time_relative` | Filter by relative time | `frame.time_relative < 10` |
| `frame.len` | Filter by packet length | `frame.len > 1000` |
| `eth.addr` | Filter by MAC address | `eth.addr == aa:bb:cc:dd:ee:ff` |
| `vlan.id` | Filter by VLAN ID | `vlan.id == 100` |
| `tcp.stream` | Filter by TCP stream index | `tcp.stream eq 5` |
| `ssl.handshake.type` | SSL handshake type | `ssl.handshake.type == 1` (Client Hello) |

## Display vs Capture Filters

### Display Filters
- Applied after capture
- Don't affect what's captured
- More complex syntax
- Example: `http and ip.src == 192.168.1.1`

### Capture Filters
- Applied during capture
- Use BPF syntax (Berkeley Packet Filter)
- Simpler syntax than display filters
- Example: `host 192.168.1.1 and port 80`

#### Common Capture Filters
| Filter | Description |
|--------|-------------|
| `host 192.168.1.1` | Traffic to/from specific host |
| `net 192.168.1.0/24` | Traffic in subnet |
| `port 80` | Traffic on port 80 |
| `portrange 1000-2000` | Traffic in port range |
| `src host 10.0.0.5` | Traffic from host |
| `dst port 22` | Traffic to port 22 |
| `tcp port 443` | TCP traffic on 443 |
| `icmp` | ICMP traffic only |
| `udp and not port 53` | UDP traffic excluding DNS |

## Practical Examples

### Basic Troubleshooting
```wireshark
# Find all traffic from a specific IP
ip.src == 192.168.1.100

# Find all HTTP GET requests
http.request.method == "GET"

# Find all failed TCP connections
tcp.flags.reset == 1
```

### Security Analysis
```wireshark
# Find potential port scans
tcp.flags.syn == 1 and tcp.flags.ack == 0

# Find DNS tunneling attempts
dns.qry.name.len > 50

# Find large HTTP POST requests
http.request.method == "POST" and http.content_length > 1000
```

### Network Performance
```wireshark
# Find TCP retransmissions
tcp.analysis.retransmission

# Find packets with high latency
tcp.analysis.ack_rtt > 0.5

# Find zero window conditions
tcp.analysis.zero_window
```

### Application Debugging
```wireshark
# Filter specific API calls
http.request.uri contains "/api/v1/login"

# Find AJAX requests
http.user_agent contains "XMLHttpRequest"

# Filter WebSocket traffic
websocket
```

## Tips
1. Right-click on any field in the packet details to easily create filters
2. Use `Ctrl+Space` for filter autocomplete
3. Save frequently used filters as filter buttons
4. Use color coding with filters to highlight important traffic
5. Combine filters with parentheses for complex logic: `(http or ssl) and ip.addr == 10.0.0.1`
```
