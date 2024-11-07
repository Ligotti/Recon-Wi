# Recon-
Mi repositorio sobre herramientas y configuraciones para la fase de reconocimiento de vulnerabilidades.


# Herramientas de escaneo
## Nmap
```shell

- nmap -sT -sV -O -p- <ip>
- nmap -sTCV <ip> 
```
### Puertos UDP
```shell
- nmap -sU -sC --top-ports 100 <ip>
```
# Herramientas de Escaneo

### Configuración de Nmap

```shell
nmap -sC -sV -oA resultados/scan 192.168.1.1
