# Shodan Search Dorks

## Basic
| Dork | Description |
|------|-------------|
| `port:80 http` | Find devices with HTTP on port 80 |
| `port:22 ssh` | Find devices with SSH on port 22 |
| `port:3389 rdp` | Find devices with RDP on port 3389 |
| `port:21 ftp` | Find devices with FTP on port 21 |
| `port:21 anonymous` | Find anonymous FTP servers |
| `port:23` | Find open Telnet ports |
| `port:443` | Find HTTPS web servers |
| `port:9200 product:Elasticsearch` | Find open Elasticsearch instances |
| `country:"US"` | Find devices in the United States |
| `country:"IN"` | Find devices in India |
| `city:"London"` | Find devices in London |
| `org:"Amazon"` | Find AWS-hosted devices |
| `org:"Amazon.com"` | Find devices belonging to Amazon.com |
| `os:"Linux"` | Find Linux systems |
| `os:"Windows 7"` | Find Windows 7 machines |
| `hostname:"github.io"` | Find GitHub Pages |
| `ssl:"Let's Encrypt"` | Find devices using Let's Encrypt SSL |

## Web Servers
| Dork | Description |
|------|-------------|
| `apache` | Find Apache servers |
| `nginx` | Find NGINX web servers |
| `product:"Apache httpd"` | Find Apache HTTP servers |
| `product:"Microsoft-IIS"` | Find Microsoft IIS servers |
| `product:"GoAhead-Webs"` | Find GoAhead WebServer devices |
| `product:"Apache Tomcat"` | Find Apache Tomcat panels |
| `product:"Jetty"` | Find Jetty web servers |
| `product:"Oracle WebLogic"` | Find Oracle WebLogic servers |
| `http.title:"index of /"` | Find open directory listings |
| `http.title:"phpMyAdmin"` | Find phpMyAdmin login pages |
| `http.title:"Welcome to OpenLiteSpeed"` | Find OpenLiteSpeed dashboards |
| `html:"Server at"` | Find Apache default pages |
| `http.component:"WordPress"` | Find WordPress sites |

## Databases
| Dork | Description |
|------|-------------|
| `product:"MongoDB"` | Find MongoDB databases |
| `port:27017 product:"MongoDB"` | Find MongoDB on default port |
| `product:"Redis"` | Find Redis servers |
| `port:5432 product:"PostgreSQL"` | Find PostgreSQL databases |
| `port:3306 product:"MySQL"` | Find MySQL databases |

## IoT/OT
| Dork | Description |
|------|-------------|
| `product:"PLC"` | Find industrial PLCs |
| `modbus` | Find Modbus industrial systems |
| `telnet port:23` | Find exposed Telnet services |
| `device:webcam` | Find open webcams |

## Remote Access
| Dork | Description |
|------|-------------|
| `vnc` | Find VNC services |
| `product:"VNC"` | Find VNC (no authentication) |
| `product:"TeamViewer"` | Find TeamViewer endpoints |
| `product:"Citrix"` | Find Citrix portals |
| `product:"OpenVPN"` | Find OpenVPN servers |

## Cloud/Containers
| Dork | Description |
|------|-------------|
| `product:"Docker"` | Find Docker instances |
| `kubernetes` | Find Kubernetes clusters |

## Network Devices
| Dork | Description |
|------|-------------|
| `net:"192.168.1.0/24"` | Find devices in specific subnet |
| `router` | Find routers |
| `firewall` | Find firewalls |

## CCTV/DVR
| Dork | Description |
|------|-------------|
| `product:"Hikvision"` | Find Hikvision cameras |
| `product:"Dahua"` | Find Dahua cameras |
| `http.title:"webcamXP"` | Find webcamXP cameras |
| `http.html:"DVR_H264 ActiveX"` | Find DVR cameras |

## Development Tools
| Dork | Description |
|------|-------------|
| `product:"Jenkins"` | Find Jenkins servers |
| `product:"GitLab"` | Find GitLab instances |
| `product:"Jupyter"` | Find Jupyter Notebooks |
| `product:"Grafana"` | Find Grafana dashboards |
| `product:"Zabbix"` | Find Zabbix interfaces |
| `product:"Splunk"` | Find Splunk interfaces |

## Email Servers
| Dork | Description |
|------|-------------|
| `port:25 smtp` | Find SMTP servers |
| `port:465 smtps` | Find SMTPS servers |
| `port:993 imaps` | Find IMAPS servers |

## File Sharing
| Dork | Description |
|------|-------------|
| `samba` | Find Samba shares |
| `nfs` | Find NFS shares |
| `ftp anonymous ok` | Find FTP with anonymous login |

## Security
| Dork | Description |
|------|-------------|
| `ssh "Protocol 2.0"` | Find SSH v2 servers |
| `tag:default-password` | Find devices with default credentials |
| `has_vuln:true` | Find vulnerable devices |
| `vuln:CVE-2017-0144` | Find EternalBlue vulnerable devices |
| `product:"nginx" version:"1.10.3"` | Find vulnerable Nginx |

## Generic
| Dork | Description |
|------|-------------|
| `has_screenshot:true` | Find devices with screenshots |
| `ssl.cert.issuer.cn:"Cloudflare Inc"` | Find Cloudflare-backed sites |
| `hostname:*.example.com` | Find wildcard hostnames |
| `isp:"Comcast Cable"` | Find Comcast devices |
| `bitcoin` | Find Bitcoin services |
| `nginx country:JP port:8080` | Find Japanese Nginx servers |
| `title:"admin panel"` | Find admin panels |
| `http.headers:"Server: Apache"` | Find Apache headers |
| `http.html:"Unauthorized"` | Find unauthorized pages |
| `tag:"vpn"` | Find VPN services |