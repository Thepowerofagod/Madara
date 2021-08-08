<p align="center">
  <img src="https://user-images.githubusercontent.com/87951795/126915552-127cb983-1670-4561-957f-65f449103882.gif" alt="animated" />
</p>

## Pentesting Resources
https://github.com/swisskyrepo/PayloadsAllTheThings  
https://pentestmonkey.net/  

## Reverse Shell
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md  
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet    

## Wordlists  
https://github.com/danielmiessler/SecLists   
https://wordlists.assetnote.io/   
https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm   

## PEASS-ng Privilege Escalation Scripts
https://github.com/carlospolop/PEASS-ng  

## Linux - Privilege Escalation
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md
 
## Linux Tools- Privilege Escalation
https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS  
https://github.com/rebootuser/LinEnum  
https://github.com/diego-treitos/linux-smart-enumeration  
https://github.com/TH3xACE/SUDO_KILLER  
https://github.com/AlessandroZ/BeRoot  
https://github.com/pentestmonkey/unix-privesc-check  
https://github.com/sleventyeleven/linuxprivchecker  

## Gobuster
https://github.com/OJ/gobuster
```
gobuster dir -u [http://<ip>:<port> or domain] -w <word list location>
```

## Unix Binaries (Used to bypass security restrictions)
https://gtfobins.github.io/

## Identify technologies on websites 
https://www.wappalyzer.com/apps

## Free Password Hash Cracker  
https://crackstation.net/    

## Hash identifier
https://gitlab.com/kalilinux/packages/hash-identifier/  

## File Shering Services
https://siasky.net/  

## HackTricks hacking trick/technique/whatever
https://book.hacktricks.xyz/

## Serving Files From Your Host
```
python3 -m  http.server 8080
```
UpDog a more advance webserver: 
https://github.com/sc0tfree/updog  

If we know ssh  
```
scp [File] [User]@[IP]:/dev/shm
```

## Nmap
```
nmap -sC -sV -oN initialScan [IP]/24
```

## Enum4linux
Enum4linux is a tool for enumerating information from Windows and Samba systems
```
 enum4linux -a [IP]
```

## Windows deep clean 
https://old.reddit.com/r/TronScript/  
- Download Tron. The download links are in the top post in /r/TronScript. If you download the self-extracting .exe file, run it and it will extract tron.bat and the \resources folder to the current directory. Copy both of them to the Desktop of the target machine.

- Tron can be run with Windows in either Safe Mode or Regular mode. Regular mode is generally recommended unless the system is severly infected.

- Right-click tron.bat and select "Run as Administrator"

## MacOS Security
https://objective-see.com/

## Shodan.io
Search for vulnerable devices (can check your own ip)  
https://www.shodan.io/
