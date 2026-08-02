---
title: Dream Job-1 Walkthrough - HTB Very Easy Sherlock | MITRE ATT&CK & Lazarus Group
description: This Sherlock introduces the MITRE ATT&CK framework, used to research and understand advanced persistent threat (APT) groups — in this case the Lazarus Group and the tactics, techniques, and procedures (TTPs) tied to Operation Dream Job.
author: dua2z3rr
date: 2025-10-26 1:00:00
categories:
  - Sherlocks
  - "Threat Intelligence"
tags: []
image: /assets/img/dream-job-1/dream-job-1-resized.png
---

## Overview

You are a junior threat intelligence analyst at a Cybersecurity firm. You have been tasked with investigating a Cyber espionage campaign known as Operation Dream Job. The goal is to gather crucial information about this operation.

### Provided Artifacts

In the compressed folder received to complete the Sherlock we have 3 hashes that we need to scan with **VirusTotal**. For the rest of the Sherlock, web research through the **MITRE ATT&CK framework** will be enough.

---

## MITRE ATT&CK: Operation Dream Job

### Attributed Threat Actor

> **Question 1:** Who conducted Operation Dream Job?

Let's search the MITRE ATT&CK framework for **Dream Job** operation.

![Desktop View](assets/img/dream-job-1/dream-job-1-1.png)

**Answer:** `Lazarus Group`

### First Observed

> **Question 2:** When was this operation first observed?

We find the answer on the right-hand side of the page we found to answer the previous question.

![Desktop View](assets/img/dream-job-1/dream-job-1-2.png)

**Answer:** `September 2019`

### Associated Campaign

> **Question 3:** There are 2 campaigns associated with Operation Dream Job. One is Operation North Star — what is the other?

The answer is found below the field for the previous answer.

**Answer:** `Operation Interception`

### Second Proxy Execution Binary

> **Question 4:** During Operation Dream Job, two system binaries were used for proxy execution. One was Regsvr32 — what was the other?

Using the `Ctrl + F` shortcut to search for words used within the page, we search for Regsvr32 and find the answer next to it.

![Desktop View](assets/img/dream-job-1/dream-job-1-3.png)

**Answer:** `Rundll32`

### Lateral Movement Technique

> **Question 5:** Which lateral movement technique did the adversary use?

Filtering the lateral movement techniques in the **ATT&CK Navigator**, we find the answer.

![Desktop View](assets/img/dream-job-1/dream-job-1-4.png)

**Answer:** `Internal Spearphishing`

### Technique ID

> **Question 6:** What is the technique ID for the previous answer?

Hovering the cursor over the light-blue box found previously, we can find the ID of the technique used by the attackers.

![Desktop View](assets/img/dream-job-1/dream-job-1-5.png)

**Answer:** `T1534`

### Remote Access Trojan

> **Question 7:** Which Remote Access Trojan did the Lazarus Group use in Operation Dream Job?

Going to the bottom of the MITRE ATT&CK framework's main page, we can see that 3 pieces of software were used during the operation. If we inspect the first one, we find the answer we're looking for.

![Desktop View](assets/img/dream-job-1/dream-job-1-6.png)

**Answer:** `DRATzarus`

### Malware Execution Technique

> **Question 8:** Which technique did the malware use for execution?

We can look for the answer in the malware's **ATT&CK Navigator**, and we'll find it under the **Execution** column.

**Answer:** `Native API`

### Sandbox Evasion Technique

> **Question 9:** Which technique did the malware use to avoid detection in a sandbox?

We repeat the procedure we used in the previous question. The answer is found in the **Defense Evasion** section.

**Answer:** `Time Based Evasion`

---

## IOC Analysis with VirusTotal

### First Hash — File Name

> **Question 10:** To answer the remaining questions, use VirusTotal and refer to the IOCs.txt file. What is the name associated with the first hash provided in the IOC file?

We enter the hash in the VirusTotal GUI and find the answer in the output.

![Desktop View](assets/img/dream-job-1/dream-job-1-8.png)

**Answer:** `IEXPLORE.exe`

### Second Hash — Creation Time

> **Question 11:** When was the file associated with the second hash in the IOC created?

We enter the second hash in the text field and read the **DETAILS** section.

![Desktop View](assets/img/dream-job-1/dream-job-1-9.png)

**Answer:** `2020-05-12 19:26:17`

### Second Hash — Parent File

> **Question 12:** What is the name of the parent execution file associated with the second hash in the IOC?

The answer is found in the **RELATIONS** section.

**Answer:** `BAE_HPC_SE.iso`

### Third Hash — Likely File Name

> **Question 13:** Examine the third hash provided. What is the name of the file likely used in the campaign that aligns with the adversary's known tactics?

We find the answer in the **DETAILS** section under **Names**.

**Answer:** `Salary_Lockheed_Martin_job_opportunities_confidential.doc`

### Third Hash — Contacted URL

> **Question 14:** Which URL was contacted on 2022-08-03 by the file associated with the third hash in the IOC file?

We find the solution in the **RELATIONS** section under **Contacted URLs**.

**Answer:** `https://markettrendingcenter.com/lk_job_oppor.docx`
