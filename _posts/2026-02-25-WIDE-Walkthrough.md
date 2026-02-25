---
title: "WIDE - HTB Challenge | Hardcoded Password"
description: "Walkthrough for WIDE challenge from Hack The Box. A reversing challenge where Ghidra is used to decompile an ELF binary and extract a hardcoded decryption key, which unlocks an encrypted dimension entry containing the flag."
author: dua2z3rr
date: 2026-02-25 1:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["reversing"]
---

## Challenge Overview

We've received reports that Draeger has stashed a huge arsenal in the pocket dimension Flaggle Alpha. You've managed to smuggle a discarded access terminal to the Widely Inflated Dimension Editor from his headquarters, but the entry for the dimension has been encrypted. Can you make it inside and take control?

---

## Solution

### Execution

Running the binary with `db.ex` as argument displays a list of dimensions, where the last entry — **Flaggle Alpha** — is marked as encrypted:

```shell
[Feb 25, 2026 - 10:11:53 (CET)] exegol-main rev_wide # ./wide db.ex  
[*] Welcome user: kr4eq4L2$12xb, to the Widely Inflated Dimension Editor [*]  
[*]    Serving your pocket dimension storage needs since 14,012.5 B      [*]  
[*]                       Displaying Dimensions....                      [*]  
[*]       Name       |              Code                |   Encrypted    [*]  
[X] Primus           | people breathe variety practice  |                [*]  
[X] Cheagaz          | scene control river importance   |                [*]  
[X] Byenoovia        | fighting cast it parallel        |                [*]  
[X] Cloteprea        | facing motor unusual heavy       |                [*]  
[X] Maraqa           | stomach motion sale valuable     |                [*]  
[X] Aidor            | feathers stream sides gate       |                [*]  
[X] Flaggle Alpha    | admin secret power hidden        |       *        [*]
```

Selecting entry `6` prompts for a WIDE decryption key.

### Decompilation with Ghidra

Loading the `wide` binary in Ghidra and inspecting the `main` function shows a call to `menu`:

![main function](assets/img/WIDE/main.png)

Inside `menu`, the binary compares the user-supplied key against the hardcoded string `sup3rs3cr3tw1d3`:

![menu function](assets/img/WIDE/menu.png)

### Flag Recovery

Using the extracted key to unlock the encrypted entry:

```
Which dimension would you like to examine? 6  
[X] That entry is encrypted - please enter your WIDE decryption key: sup3rs3cr3tw1d3  
HTB{som3_str1ng5_4r3_w1d3}
```

**Flag obtained.**
