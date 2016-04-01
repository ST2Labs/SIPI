#Simple IP Information Tools (sIPI) 
##for IP Reputation Data Analysis

[[@SVTCloud]] Simple IP Information Tool [[@st2labs]]

__Author__: Julian J. Gonzalez Caracuel - Twitter: @rhodius | @seguriadxato2 | @st2labs | @svtcloud

__Vesion__: 0.1

# Abstracts

This tool is aimed for Incident Response Team and anyone what's want to know the behaviour of the "suspicious" IP Address.
The tools do search looking for reputation info from a set of open threat intelligence  sources. Information about this IP like malware activity, malicious activity, blacklist, spam and botnet activity.

__Depedencies__:
- request
- shodan

__Installation__:

	pip install requests & easy_install shodan
	git clone "repositori"
	config API token into config.json

try:
$> python sipi.py any_ip -A

# Descripcion
 
 [[@SVTCloud] Simple IP Information Tool [[@st2labs]]

     sIPi - is a free reconnaissance tool for obtain IP Address Information from
     many Open Sources: cymon.io | shoda.io | ipinfo.io

   Julian J. Gonzalez Caracuel - @rhodius
   Version: 0.1
 
   Es una herramienta que analiza una IP o lista de IP, obteniendo como resultado información sobre:

		- reputación / actividad
		- nivel de exposición 
		- geolocalización
   
   Reputación / detección de la IP en lista negras según las siguientes categorias:
    
	   Source: cymon.io - Cymon is the largest open tracker of malware, phishing, botnets, spam, and more
	   
	   ['malware',
		   'botnet',
		   'spam',
		   'phishing',
		   'malicious activity',
		   'blacklist',
		   'dnsbl']

	Nivel de exposición:
	
		Source: shodan.io - Shodan is the world's first search engine for Internet-connected devices.
		
		Obtiene información toda la dirección IP que tiene SHODAN sobre la dirección IP, dependiendo del nivel de acceso al motor SHODAN 
		se podra obtener información con mayor cantidad de datos (número de puertos, banner, geolocalización)
		
	Geolocalización:
	
		Source: ipinfo.io
		
		Obtiene información simple de la dirección IP, geolocalización e información sobre el ASN, permite un ratio de 1000/day

# Instalacion Requisitos
 
	cymon.io  - Necesita token de autenticación - usuario registrado ratio: 1000/days
	shodan.io - Necesita token de autenticación - usuario registrado limite 100 resultados, puertos limitados
	
   La configuración de los token, se introduce en Fichero: config.json, que debe estar en el directorio donde se ejecuta sipi.py
   << API token from all service is setting up into a "config.json" filename place in the root directory >>

 Dependencias
   
   requests
   
	pip install requests
   
   shodan
   
	easy_install shodan

   Linux & Windows
 

 
# Examples | Ejemplos
  
	 Buscar información en todas las categorias de reputación, nivel de exposición & ip información
	 Get Info to IP's list filename in All categoty from cymon, and adds info from Shodan & IPInfo
	 $> python sipi.py list_ip -A -s -i

	 Obtener información sobre la IP en lista de SPAM, nivel de exposición & ip información
	 Get Info to IP's list filename only in SPAM categoty from cymon, and adds info from Shodan & IPInfo
	 $> python sipi.py list_ip -t spam -s -i
	 
	 Obtener información sobre la lista de IP en reputación a nivel de Malware
	 Get Info to IP's list filename only in MALWARE categoty from cymon with 1 day ago and 1000 entry limits
	 $> python sipi.py list_ip -t malware -d 1 -l 1000
	 
		-d <days[1-3]> Solamente se puede analizar el nivel de reputación de la IP hace 3 días
		If you don't find anythings, maybe events was more than 3 day ago, please try to use -d 4 options
		Para más de 3 días utilizar -d 4
		
		-l <limite> Controlar el número de resultados donde analizar la IP - Default: 100
		
# Output Example:
 
 $> python sipi.py lista.txt -d 4 -A

   _______ _____  _____  _____
   |______   |   |_____]   |
   ______| __|__ |       __|__
   ---------------------------

   [[@SVTCloud] Simple IP Information Tool [[@st2labs]]

     sIPi - is a free recorn tool for obtain IP Address Information from
     many Open Sources: cymon.io | shoda.io | ipinfo.io

   Julian J. Gonzalez Caracuel - @rhodius
   Version: 0.1

     [!] This IP ['83.55.23.240s'] is not valid & have been removed from searching
   
   
     If days more than 3, auto change mode is active
     [ip_blacklist > ip_events] to obtain Ip Info
   
   
     ++++++++++++++++++++++++++++++++++++++
     + Info obtain from: http://cymon.io  +
     +     Checking for ip_events
     ++++++++++++++++++++++++++++++++++++++
   
   
     +---------------------------------+
     +-Events for IP:93.76.61.78
     +---------------------------------+
   
       +--
   
       [!] IP 93.76.61.78 found in malicious activity BlackList
       Detected by: [u'esentire threat labs']
   
       --+
   
       [NOT_FOUND] IP 93.76.61.78  in this CATEGORIES:['malware', 'botnet', 'spam', 'phishing', 'blacklist', 'dnsbl']
   
   
     +---------------------------------+
     +-Events for IP:93.183.250.196
     +---------------------------------+
   
       +--
   
       [!] IP 93.183.250.196 found in malicious activity BlackList
       Detected by: [u'esentire threat labs']
   
       --+
   
       [NOT_FOUND] IP 93.183.250.196  in this CATEGORIES:['malware', 'botnet', 'spam', 'phishing', 'blacklist', 'dnsbl']
   
   
     +---------------------------------+
     +-Events for IP:176.101.204.172
     +---------------------------------+
   
       +--
   
       [!] IP 176.101.204.172 found in malicious activity BlackList
       Detected by: [u'esentire threat labs']
   
       --+
   
       [NOT_FOUND] IP 176.101.204.172  in this CATEGORIES:['malware', 'botnet', 'spam', 'phishing', 'blacklist', 'dnsbl']
   
#License Info

	This is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation version 2 of the License.
	
	This is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along it; if not, write to the Free Software
	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
