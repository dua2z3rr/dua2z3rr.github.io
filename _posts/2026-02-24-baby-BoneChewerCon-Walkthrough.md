---
title: "baby BoneChewerCon - HTB Easy Challenge | Symfony Debug Mode Information Disclosure"
description: "Walkthrough for baby BoneChewerCon challenge from Hack The Box. An easy web challenge where a maintenance page with a booking form throws a Symfony debugger error. The debug mode exposes sensitive environment variables including the APP_KEY which contains the flag."
author: dua2z3rr
date: 2026-02-24 1:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["web"]
---

## Challenge Overview

Due to heavy workload for the upcoming baby BoneChewerCon event, the website is under maintenance and it errors out, but the debugger is still enabled in production!! I think the devil is enticing us to go and check out the secret key.

---

## Solution

### Website Inspection

When we load the site, we're presented with a page communicating that due to high system demand, the site is under maintenance:

![home-page-sito](assets/img/baby-BoneChewerCon/homepage.png)

At the bottom we can make a reservation, but when we click it, the debugger appears with an error. The Symfony error states that the POST method is not allowed:

![debugger](assets/img/baby-BoneChewerCon/debugger-error.png)

### Flag Discovery

In the debugger parameters we can find the flag in the value of the APP-KEY variable:

![app-key](assets/img/baby-BoneChewerCon/APP-KEY.png)

**Flag obtained.**