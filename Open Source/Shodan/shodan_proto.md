| Protocol  | Facet                  | Description                     | Example                          | Data Type |
|-----------|------------------------|---------------------------------|----------------------------------|-----------|
| HTTP      | http.title             | Web page title                  | http.title:"Admin Login"         | string    |
| HTTP      | http.status            | HTTP status code                | http.status:200                  | integer   |
| HTTP      | http.html              | HTML content                    | http.html:"password"             | string    |
| HTTP      | http.headers.server    | Server header                   | http.headers.server:"Apache"      | string    |
| HTTP      | http.component         | Web component                   | http.component:"react"           | string    |
| HTTP      | http.favicon.hash      | Favicon hash                    | http.favicon.hash:-123456789     | integer   |
| HTTP      | http.robots.txt        | Robots.txt content              | http.robots.txt:"Disallow: /admin" | string  |
| SSL/TLS   | ssl.cert.issuer.cn     | SSL issuer common name          | ssl.cert.issuer.cn:"Let's Encrypt" | string |
| SSL/TLS   | ssl.cert.subject.cn    | SSL subject common name         | ssl.cert.subject.cn:"*.google.com" | string |
| SSL/TLS   | ssl.version            | SSL/TLS version                 | ssl.version:"TLSv1.2"            | string    |
| SSL/TLS   | ssl.cert.expired       | Expired certificate             | ssl.cert.expired:true            | boolean   |
| SSL/TLS   | ssl.cert.serial        | Certificate serial               | ssl.cert.serial:"123456abc"      | string    |
| SSL/TLS   | ssl.ja3s               | JA3S fingerprint                | ssl.ja3s:"a387..."               | string    |
| SSH       | ssh.banner             | SSH server banner               | ssh.banner:"OpenSSH"             | string    |
| SSH       | ssh.type               | SSH implementation              | ssh.type:"dropbear"              | string    |
| SSH       | ssh.hassh              | HASSH fingerprint               | ssh.hassh:"a1b2..."              | string    |
| SSH       | ssh.cipher             | Encryption cipher               | ssh.cipher:"aes256-ctr"          | string    |
| SSH       | ssh.mac                | Message auth code               | ssh.mac:"hmac-sha2-256"          | string    |
| FTP       | ftp.anonymous          | Anonymous login                 | ftp.anonymous:true               | boolean   |
| FTP       | ftp.banner             | FTP server banner               | ftp.banner:"vsFTPd"              | string    |
| FTP       | ftp.features           | FTP features                    | ftp.features:"AUTH TLS"          | string    |
| DNS       | dns.records            | DNS record types                | dns.records:"MX"                 | string    |
| DNS       | dns.resolver           | DNS resolver IP                 | dns.resolver:"8.8.8.8"           | string    |
| DNS       | dns.port               | DNS port number                 | dns.port:53                      | integer   |
| SMTP      | smtp.banner            | SMTP server banner              | smtp.banner:"Postfix"            | string    |
| SMTP      | smtp.starttls          | STARTTLS support                | smtp.starttls:true               | boolean   |
| SMTP      | smtp.ehlo              | EHLO response                   | smtp.ehlo:"ESMTP"                | string    |
| RDP       | rdp.protocol           | RDP protocol version            | rdp.protocol:"HYBRID"            | string    |
| RDP       | rdp.cookie             | RDP session cookie              | rdp.cookie:"123abc"              | string    |
| RDP       | rdp.credssp            | CredSSP support                 | rdp.credssp:true                 | boolean   |
| MySQL     | mysql.version          | MySQL version                   | mysql.version:"8.0.26"           | string    |
| MySQL     | mysql.banner           | MySQL banner                    | mysql.banner:"5.7.35"            | string    |
| MySQL     | mysql.protocol         | Protocol version                | mysql.protocol:10                | integer   |
| SIP       | sip.banner             | SIP server banner               | sip.banner:"Asterisk"            | string    |
| SIP       | sip.methods            | SIP methods                     | sip.methods:"INVITE"             | string    |
| SIP       | sip.useragent          | SIP user agent                  | sip.useragent:"eyeBeam"          | string    |
| SNMP      | snmp.community         | SNMP community                  | snmp.community:"public"          | string    |
| SNMP      | snmp.sysdesc           | System description              | snmp.sysdesc:"Cisco IOS"         | string    |
| SNMP      | snmp.contact           | Admin contact                   | snmp.contact:"admin@company.com" | string    |
| Industrial | modbus.device         | Modbus device ID                | modbus.device:1                  | integer   |
| Industrial | bacnet.vendor         | BACnet vendor                   | bacnet.vendor:"Siemens"          | string    |
| Industrial | s7.shortname          | S7 PLC name                     | s7.shortname:"PLC_1"             | string    |
| ICS       | fox.info               | Fox device info                 | fox.info:"DIGI"                  | string    |
| ICS       | omron.header           | Omron header                    | omron.header:"FINS"              | string    |
| ICS       | pcworx.info            | PCWorx info                     | pcworx.info:"WAGO"               | string    |
| VNC       | vnc.banner             | VNC server banner               | vnc.banner:"TightVNC"            | string    |
| VNC       | vnc.auth               | VNC auth type                   | vnc.auth:"None"                  | string    |
| VNC       | vnc.width              | Screen width                    | vnc.width:1920                   | integer   |
| RTSP      | rtsp.banner            | RTSP server banner              | rtsp.banner:"DSS"                | string    |
| RTSP      | rtsp.methods           | RTSP methods                    | rtsp.methods:"DESCRIBE"          | string    |
| RTSP      | rtsp.status            | RTSP status                     | rtsp.status:200                  | integer   |
| Telnet    | telnet.banner          | Telnet banner                   | telnet.banner:"Ubuntu"           | string    |
| Telnet    | telnet.do              | DON'T option                    | telnet.do:"\xFF\xFD\x18"         | hex       |
| Telnet    | telnet.will            | WILL option                     | telnet.will:"\xFF\xFB\x01"       | hex       |
| MongoDB   | mongodb.version        | MongoDB version                 | mongodb.version:"4.4.6"          | string    |
| MongoDB   | mongodb.nonce          | Authentication nonce            | mongodb.nonce:"123abc"           | string    |
| MongoDB   | mongodb.ismaster       | IsMaster response               | mongodb.ismaster:true            | boolean   |
