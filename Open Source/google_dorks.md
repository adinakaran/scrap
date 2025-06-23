```markdown
# Google Dorks Cheat Sheet

## Table of Contents
- [Basic](#basic)
- [Login Pages](#login-pages)
- [Sensitive Files](#sensitive-files)
- [Vulnerable Systems](#vulnerable-systems)
- [Network Devices](#network-devices)
- [Database](#database)
- [Security](#security)
- [Cameras](#cameras)
- [Cloud Services](#cloud-services)
- [WordPress](#wordpress)
- [GitHub](#github)
- [Documentation](#documentation)
- [Backups](#backups)
- [IoT](#iot)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Social Media](#social-media)

## Basic

| Dork | Description |
|------|-------------|
| `site:example.com` | Search only within specified domain |
| `inurl:admin` | URLs with 'admin' in the path |
| `intitle:"index of"` | Directory listings |
| `filetype:pdf` | Find PDF files |
| `filetype:pdf site:example.com` | Find PDF files on a site |
| `ext:php` | Find PHP files |
| `ext:sql` | Find SQL database files |
| `ext:sql | ext:dbf | ext:mdb` | Database files |
| `ext:log` | Find log files |
| `ext:conf` | Find configuration files |
| `ext:xml` | XML files exposed |
| `ext:json` | JSON files exposed |
| `ext:bak` | Backup files |
| `ext:old` | Old files |
| `ext:inc` | Include files |
| `cache:` | View cached versions of pages |
| `link:example.com` | Sites that link to example.com |

## Login Pages

| Dork | Description |
|------|-------------|
| `inurl:login` | Find login pages |
| `inurl:signin` | Find sign-in pages |
| `inurl:signup` | Signup pages |
| `inurl:register` | Registration pages |
| `intitle:"login"` | Pages with 'login' in title |
| `inurl:wp-login.php` | Find WordPress login pages |
| `inurl:/admin/login.php` | Find admin login portals |
| `inurl:admin intitle:login` | Admin login pages |

## Sensitive Files

| Dork | Description |
|------|-------------|
| `intitle:"index of" "parent directory"` | Find open directories |
| `intext:'Index of /admin'` | Pages with admin directories listed |
| `intext:'Index of /password'` | Exposed password directories |
| `intext:'Index of /mail'` | Mail directory listing |
| `intext:'Index of /user'` | User directories |
| `intext:'Index of /customer'` | Customer data directories |
| `intext:'Index of /private'` | Private folders |
| `intext:'Index of /.ssh'` | SSH folder exposures |
| `intext:'Index of /.bash_history'` | Shell history exposed |
| `intext:'Index of /.env'` | Environment variables exposed |
| `inurl:/phpinfo.php` | Find PHP info pages |
| `intitle:"phpinfo()"` | Exposed phpinfo pages |
| `inurl:/.git/index` | Find exposed Git repositories |
| `inurl:/.svn` | Exposed SVN repositories |
| `filetype:env` | .env files exposed |
| `filetype:env DB_USERNAME DB_PASSWORD` | Find .env files with credentials |
| `ext:sql intext:password` | Find SQL files containing passwords |
| `filetype:log intext:password` | Find log files with passwords |
| `intext:'confidential'` | Search for confidential information |
| `'ssn' filetype:xls` | SSNs in Excel files |
| `'password' filetype:log` | Passwords in log files |
| `'passwd' filetype:txt` | UNIX password files |
| `'sensitive data' filetype:pdf` | PDFs with sensitive data |
| `'confidential' filetype:doc` | DOCs marked confidential |
| `'Not for Distribution' filetype:xls` | Restricted Excel files |

## Vulnerable Systems

| Dork | Description |
|------|-------------|
| `inurl:/shell.php` | Find potential web shells |
| `inurl:/console/` | Find development consoles |
| `intitle:"Apache Tomcat" "Manager"` | Find Tomcat manager |
| `intext:"Powered by phpMyAdmin"` | Find phpMyAdmin instances |
| `inurl:/cgi-bin/` | Find CGI directories |
| `intitle:"Welcome to Joomla!"` | Joomla default pages |
| `intitle:"Apache2 Ubuntu Default Page"` | Apache default pages |
| `intitle:"Welcome to nginx!"` | Nginx default pages |
| `'Powered by vBulletin'` | vBulletin forum sites |
| `'Powered by phpBB'` | phpBB forum sites |
| `'Powered by WordPress'` | WordPress sites |

## Network Devices

| Dork | Description |
|------|-------------|
| `inurl:/cgi-bin/login.cgi` | Find router login pages |
| `intitle:"RouterOS" "Winbox"` | Find MikroTik devices |
| `intext:"Welcome to nginx"` | Find nginx servers |
| `intitle:"Apache Status" "Server Version"` | Find Apache server info |
| `inurl:server-status` | Apache server-status pages |
| `inurl:dashboard` | Admin dashboards |
| `inurl:config` | Possible configuration panels |
| `inurl:setup` | Setup/configuration pages |

## Database

| Dork | Description |
|------|-------------|
| `filetype:mdb` | Find Microsoft Access databases |
| `inurl:/phpmyadmin/` | Find phpMyAdmin interfaces |
| `intitle:"MySQL dump" filetype:sql` | Find MySQL dumps |
| `inurl:/db/main.php` | Find database admin interfaces |
| `inurl:phpmyadmin` | phpMyAdmin panels |

## Security

| Dork | Description |
|------|-------------|
| `filetype:rdp` | Find RDP connection files |
| `filetype:ppk` | Find PuTTY private keys |
| `intext:"BEGIN RSA PRIVATE KEY"` | Find private keys |
| `filetype:pem intext:PRIVATE KEY` | Find PEM private keys |
| `ext:txt intext:API_KEY` | Find API keys in text files |

## Cameras

| Dork | Description |
|------|-------------|
| `inurl:/view/view.shtml` | Find webcam feeds |
| `intitle:"webcamXP 5"` | Find webcamXP instances |
| `intext:"Network Camera" "User Guide"` | Find IP cameras |

## Cloud Services

| Dork | Description |
|------|-------------|
| `inurl:/aws/credentials` | Find AWS credentials |
| `filetype:json api.googlemaps key` | Find Google Maps API keys |
| `intext:"bucket_name" filetype:env` | Find cloud bucket names |
| `site:pastebin.com` | Search leaked data on Pastebin |
| `site:github.com` | Look for sensitive files/code on GitHub |
| `site:trello.com` | Trello public boards |
| `site:drive.google.com` | Open Google Drive files |
| `site:onedrive.live.com` | Open Microsoft OneDrive files |

## WordPress

| Dork | Description |
|------|-------------|
| `inurl:/wp-admin` | WordPress admin panel |
| `inurl:/wp-content` | Find WordPress sites |
| `inurl:/wp-content/uploads/` | Find WordPress uploads |
| `inurl:/wp-config.php` | Find WordPress config files |
| `intitle:"WordPress" inurl:wp-login` | Find WordPress login |

## GitHub

| Dork | Description |
|------|-------------|
| `site:github.com intext:password` | Find passwords on GitHub |
| `site:github.com intext:API_KEY` | Find API keys on GitHub |
| `site:github.com filename:.env` | Find .env files on GitHub |

## Documentation

| Dork | Description |
|------|-------------|
| `intitle:"index of" "README.md"` | Find README files |
| `filetype:docx intext:"confidential"` | Find confidential docs |
| `filetype:xlsx intext:"password"` | Find Excel files with passwords |
| `'index of' 'backup'` | Backup directories |
| `'index of' 'uploads'` | Upload directories |

## Backups

| Dork | Description |
|------|-------------|
| `filetype:bak intext:"db_"` | Find database backups |
| `intitle:"index of" "backup"` | Find backup directories |
| `filetype:zip intext:"backup"` | Find backup zip files |

## IoT

| Dork | Description |
|------|-------------|
| `intitle:"Device Manager"` | Find IoT device managers |
| `intext:"Hikvision" "Camera"` | Find Hikvision cameras |
| `inurl:/cgi-bin/userLogin.cgi` | Find IoT login portals |

## Vulnerability Scanning

| Dork | Description |
|------|-------------|
| `inurl:/robots.txt` | Find robots.txt files |
| `inurl:/sitemap.xml` | Find sitemap files |
| `inurl:/.well-known/security.txt` | Find security policy files |

## Social Media

| Dork | Description |
|------|-------------|
| `inurl:/profiles/` | Find user profiles |
| `intext:"@gmail.com" filetype:csv` | Find email lists |
| `inurl:/friends/` | Find friend connections |

## Usage Tips
1. Combine dorks with `AND`, `OR`, and `NOT` operators
   - Example: `inurl:admin AND site:example.com`
2. Use quotes for exact phrase matches
3. Use parentheses for complex queries
   - Example: `(inurl:login OR inurl:signin) AND site:example.com`
4. Use `-` to exclude terms
   - Example: `filetype:pdf -site:example.com`
5. Use `*` as a wildcard
   - Example: `intitle:"index of *"`

## Legal Considerations
⚠️ **Important:** Use these dorks responsibly and only on systems you own or have permission to test. Unauthorized scanning may violate laws and terms of service.

## Resources
- [Google Advanced Search Operators](https://support.google.com/websearch/answer/2466433)
- [Google Hacking Database (GHDB)](https://www.exploit-db.com/google-hacking-database)
- [Google Dorking Guide](https://en.wikipedia.org/wiki/Google_hacking)
```

