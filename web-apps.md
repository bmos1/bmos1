# URL safe encoding
* use Burp to decode URL easily

```python
import urllib.parse
urllib.parse.quote('/La Niña/', safe='')
```

# Common HTTP Headers
* https://en.wikipedia.org/wiki/List_of_HTTP_header_fields
* Server: Reveals the SW running the Web Server
* Forwarded: Provides the server with diagnostics for requests that come via proxy.

# JavaScript 101
* security researcher focus on hidden input fields
* https://developer.mozilla.org/en-US/docs/Web/JavaScript
* https://developer.mozilla.org/en-US/docs/Learn/Front-end_web_developer

```javascript
var int = 1
var str = "somestring"
var obj = {foo: "bar"} // key value pairs
vor obj = {sub: function (a, b) {return a - b;}}

var book = { 
  title: 'Die Physiker', 
  author: 'Friedrich Dürrenmatt', 
  toString: function() { 
    return this.title + " von " + this.author; 
  }
};
book.toString()

document.getElementsByTagName("a")
document.getElementsByTagName("input")
```

# HTTP Base and Routing
* Base folder on linux
* robots.txt to disallow crawler access
* sitemap.xml to specify bots access

```bash
ll /var/www/html/default.html
ll /var/www/html/index.php
ll /var/www/html/robots.txt
ll /var/www/html/sitemap.xml
```

Control crawling with "robots.txt"

```
User-agent: *
Allow: /index
Disallow: /what-is-a-bot
User-agent: googlebot
Disallow: /no-google
User-agent: bingbot
Disallow: /no-bing
User-agent: baiduspider
Disallow: /

Sitemap: https://www.example.com/sitemap.xml
Sitemap: https://www.example.com/de-de/sitemap.xml
```
Explain site with "sitemap.xml"

```bash
<urlset>
<url>
<loc>/index</loc>
<lastmod>2021-05-24</lastmod>
<changefreq>monthly</changefreq>
<priority>0.8</priority>
</url>
</urlset>
```

# SQL Databases 101
* JOIN to combine row from different tables with FK
* **UNION to combine rows from multiple tables without FK**
* but this requires to specify the same number of columns

```sql
SHOW tables;
SELECT email FROM users;
SELECT id, email FROM users WHERE firstname = 'Andrew' OR id = 2
INSERT INTO users (email) VALUES ('a.user@gmail.com'); 
UPDATE users SET email = 'some.user@gmail.com' WHERE email = 'a.user@gmail.com';
DELETE users WHERE email ~ 'some.user';
SELECT firstname, locations FROM users JOIN locations ON users.id=locations.userid; 
SELECT id, email FROM users
UNION
SELECT id, email FROM admins;
```
