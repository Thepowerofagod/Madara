## Information Gathering
- IP address.
- Domain name info.
- Technologies used.
- Other websites on the same server.
- DNS records.
- Unlisted files, sub-domains, directories(/login, /phpinfo.php, /phpMyAdmin, /robots.txt).

1. Whois Lookup  - Find info about the owner of the target.
    - http://whois.domaintools.com/
2. Netcraft Site Report - Shows technologies used on the target.
    - https://sitereport.netcraft.com/
3. Wappalyzer - Identify technologies on websites 
    - https://www.wappalyzer.com/
4. Robtex DNS lookup - Shows comprehensive info about the target website.
    - https://www.robtex.com
5. Reverse IP Lookup
    - could not find any vulnerabilities in your target website,
you can try to hack into any other website
that is installed in the same server.
        - use Robtex DNS lookup
        - use bing.com ip:[ip]
        - use whois.domaintools.com
6. Discovering Subdomains
    - https://github.com/guelfoweb/knock
```
knockpy google.com
```
7. Discovering Files and Directories
- dirb
```
dirb [http://<ip>:<port> or domain] <word list location>
```
- Gobuster
    - https://github.com/OJ/gobuster
```
gobuster dir -u [http://<ip>:<port> or domain] -w <word list location>
```
recomendet wordlist https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt
- Look in /robots.txt
