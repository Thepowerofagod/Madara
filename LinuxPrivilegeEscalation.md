## Linux Privilege Escalation

![68747470733a2f2f7062732e7477696d672e636f6d2f6d656469612f44415a73453256555141415f62705a2e6a7067](https://user-images.githubusercontent.com/87951795/131122135-fea9fb57-8ea1-4a2a-8969-347305dc1814.jpg)

Windows / Linux Local Privilege Escalation Workshop: https://github.com/sagishahar/lpeworkshop

Tools:
- https://github.com/diego-treitos/linux-smart-enumeration
- https://github.com/rebootuser/LinEnum

Other Tools:
- https://github.com/linted/linuxprivchecker
- https://github.com/AlessandroZ/BeRoot
- http://pentestmonkey.net/tools/audit/unix-privesc-check


The kernel exploit:
Should be a last resort as kernel exploits can often be unstable and may be one shot or cause a system crash.
1. Enumerate kernel version (uname -a).
2. Find matching exploits use Linux Exploit Suggester 2 or (Google, ExploitDB, GitHub).  
  - https://github.com/jondonas/linux-exploit-suggester-2
```
./linux-exploit-suggester.pl -k (karnel vertion from uname -a)

or

searchsploit linux kernel 2.6.32 priv esc
searchsploit linux kernel 2.6 debian priv esc
```
3. Compile and run.
```
gcc -pthread c0w.c -o c0w
./c0w
/usr/bin/passwd
```






