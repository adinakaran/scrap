```markdown
# Shodan Dork Cheat Sheet

## Table of Contents
- [Basic](#basic)
- [Web Servers](#web-servers)
- [Databases](#databases)
- [Cloud Services](#cloud-services)
- [Network Devices](#network-devices)
- [Vulnerable Systems](#vulnerable-systems)
- [IoT](#iot)
- [Remote Access](#remote-access)
- [Security](#security)
- [Certificates](#certificates)
- [Industrial Control](#industrial-control)
- [VPN Services](#vpn-services)
- [Email](#email)
- [Specialized](#specialized)

## Basic

| Dork | Description |
|------|-------------|
| `services.port:80` | Find devices with port 80 open |
| `services.port:443` | Find HTTPS services |
| `services.port:22` | Find SSH servers |
| `services.port:3389` | Find RDP services |
| `location.country:"US"` | Devices in United States |
| `location.country_code:"DE"` | Devices in Germany |
| `autonomous_system.name:"CLOUDFLARENET"` | Cloudflare-hosted assets |
| `services.service_name:"HTTP"` | All HTTP services |

## Web Servers

| Dork | Description |
|------|-------------|
| `services.http.response.html_title:"Login"` | Pages with 'Login' title |
| `services.http.response.body:"admin"` | Pages containing 'admin' |
| `services.http.response.favicon.hash:-335242539` | F5 BIG-IP devices |
| `services.http.response.headers.server:"Apache"` | Apache servers |
| `services.http.response.headers.server:"nginx"` | Nginx servers |
| `services.http.response.status_code:200` | Successful HTTP responses |
| `services.http.response.meta.robots:"noindex"` | Pages with noindex |

## Databases

| Dork | Description |
|------|-------------|
| `services.service_name:"MongoDB"` | MongoDB instances |
| `services.service_name:"PostgreSQL"` | PostgreSQL servers |
| `services.service_name:"MySQL"` | MySQL servers |
| `services.service_name:"Redis"` | Redis instances |
| `services.port:27017` | MongoDB default port |
| `services.port:5432` | PostgreSQL default port |

## Cloud Services

| Dork | Description |
|------|-------------|
| `services.cloud.provider:"AWS"` | Amazon Web Services |
| `services.cloud.provider:"GCP"` | Google Cloud Platform |
| `services.cloud.provider:"Azure"` | Microsoft Azure |
| `services.service_name:"Kubernetes"` | Kubernetes clusters |

## Network Devices

| Dork | Description |
|------|-------------|
| `services.banner:"Cisco"` | Cisco devices |
| `services.banner:"Juniper"` | Juniper devices |
| `services.banner:"Fortinet"` | Fortinet devices |
| `services.product:"RouterOS"` | MikroTik routers |

## Vulnerable Systems

| Dork | Description |
|------|-------------|
| `services.tls.certificates.leaf_data.issuer.organization:"Let's Encrypt"` | Let's Encrypt certs |
| `services.http.response.body:"phpMyAdmin"` | phpMyAdmin interfaces |
| `services.http.response.body:"Drupal"` | Drupal CMS |
| `services.http.response.body:"WordPress"` | WordPress sites |

## IoT

| Dork | Description |
|------|-------------|
| `services.product:"Hikvision"` | Hikvision cameras |
| `services.product:"Dahua"` | Dahua cameras |
| `services.banner:"webcam"` | Webcam interfaces |
| `services.product:"PLC"` | Programmable Logic Controllers |

## Remote Access

| Dork | Description |
|------|-------------|
| `services.service_name:"VNC"` | VNC servers |
| `services.service_name:"RDP"` | Remote Desktop |
| `services.service_name:"TeamViewer"` | TeamViewer hosts |

## Security

| Dork | Description |
|------|-------------|
| `services.tls.version:"TLS 1.0"` | Insecure TLS 1.0 |
| `services.heartbleed_vulnerable:true` | Heartbleed vulnerable |
| `services.http.response.headers:"X-Powered-By: PHP/5.6"` | Outdated PHP |

## Certificates

| Dork | Description |
|------|-------------|
| `services.tls.certificates.leaf_data.subject.common_name:"*.google.com"` | Google certs |
| `services.tls.certificates.leaf_data.issuer.common_name:"Let's Encrypt"` | Let's Encrypt |
| `services.tls.certificates.leaf_data.expired:true` | Expired certificates |

## Industrial Control

| Dork | Description |
|------|-------------|
| `services.product:"Modbus"` | Modbus devices |
| `services.product:"Siemens"` | Siemens PLCs |
| `services.product:"Allen-Bradley"` | Allen-Bradley PLCs |

## VPN Services

| Dork | Description |
|------|-------------|
| `services.product:"OpenVPN"` | OpenVPN servers |
| `services.product:"PPTP"` | PPTP VPNs |
| `services.product:"Cisco AnyConnect"` | Cisco VPNs |

## Email

| Dork | Description |
|------|-------------|
| `services.port:25` | SMTP servers |
| `services.port:465` | SMTPS servers |
| `services.port:993` | IMAPS servers |
| `services.banner:"Microsoft ESMTP"` | Microsoft Exchange |

## Specialized

| Dork | Description |
|------|-------------|
| `services.http.response.body:"Solr Admin"` | Apache Solr |
| `services.http.response.body:"Kibana"` | Kibana dashboards |
| `services.http.response.body:"Jenkins"` | Jenkins CI |
| `services.http.response.body:"Grafana"` | Grafana dashboards |

## Usage Tips
1. Combine dorks with `AND`, `OR`, and `NOT` operators for advanced searches
   - Example: `services.port:80 AND location.country:"US"`
2. Use quotes for exact matches
3. Wildcards are supported with `*` character
4. Filter by date with `after:"YYYY-MM-DD"` and `before:"YYYY-MM-DD"`
5. Sort results with `sort:score` or `sort:timestamp`

## Resources
- [Official Shodan Search Guide](https://help.shodan.io/the-basics/search-query-fundamentals)
- [Shodan Search Filters](https://www.shodan.io/search/filters)
- [Shodan Dork Examples](https://github.com/jakejarvis/awesome-shodan-queries)
```
