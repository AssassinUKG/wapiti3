# wapiti3

## Source
https://wapiti.sourceforge.io/

## Description

Wapiti allows you to audit the security of your websites or web applications.

It performs "black-box" scans (it does not study the source code) of the web application by crawling the webpages of the deployed webapp, looking for scripts and forms where it can inject data.

Once it gets the list of URLs, forms and their inputs, Wapiti acts like a fuzzer, injecting payloads to see if a script is vulnerable

## Function

- File disclosure (Local and remote include/require, fopen, readfile...)
- Database Injection (PHP/JSP/ASP SQL Injections and XPath Injections)
- XSS (Cross Site Scripting) injection (reflected and permanent)
- Command Execution detection (eval(), system(), passtru()...)
- CRLF Injection (HTTP Response Splitting, session fixation...)
- XXE (XML External Entity) injection
- SSRF (Server Side Request Forgery)
- Use of know potentially dangerous files (thanks to the Nikto database)
- Weak .htaccess configurations that can be bypassed
- Presence of backup files giving sensitive information (source code disclosure)
- Shellshock (aka Bash bug)
- Open Redirects
- Uncommon HTTP methods that can be allowed (PUT)
- CSRF (Cross Site Request Forgery)
- Basic CSP Evaluator
- Brute Force login form (using a dictionary list)
- Cheking HTTP security headers
- Checking cookie security flags (secure and httponly flags)

## Screenshot
![](/assets/Capture.PNG)

## Install
```
pip install wapiti3
```
or
```
pip3 install wapiti3
```

## Usage

```
wapiti -u http://192.168.222.99:33333/
```

Wapiti-3.0.3 (wapiti.sourceforge.net)

usage:

wapiti [-h] [-u URL] [--scope {page,folder,domain,url,punk}]

              [-m MODULES_LIST] [--list-modules] [--update] [-l LEVEL]
              [-p PROXY_URL] [--tor] [-a CREDENTIALS]
              [--auth-type {basic,digest,kerberos,ntlm,post}]
              [-c COOKIE_FILE] [--skip-crawl] [--resume-crawl]
              [--flush-attacks] [--flush-session] [--store-session PATH]
              [--store-config] [-s URL] [-x URL] [-r PARAMETER]
              [--skip PARAMETER] [-d DEPTH] [--max-links-per-page MAX]
              [--max-files-per-dir MAX] [--max-scan-time SECONDS]
              [--max-attack-time SECONDS] [--max-parameters MAX] [-S FORCE]
              [-t SECONDS] [-H HEADER] [-A AGENT] [--verify-ssl {0,1}]
              [--color] [-v LEVEL] [-f FORMAT] [-o OUPUT_PATH]
              [--external-endpoint EXTERNAL_ENDPOINT_URL]
              [--internal-endpoint INTERNAL_ENDPOINT_URL]
              [--endpoint ENDPOINT_URL] [--no-bugreport] [--version]
              
              

