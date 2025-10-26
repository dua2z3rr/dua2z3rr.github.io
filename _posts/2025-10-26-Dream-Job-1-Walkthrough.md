---
title: "Dream Job-1"
description: In questo Sherlock, i giocatori verranno introdotti al framework MITRE ATT&CK, uno strumento utilizzato per ricercare e comprendere i gruppi di minaccia avanzata persistente (APT). In particolare, i giocatori si concentreranno sul gruppo APT noto come Lazarus Group. Durante l'esecuzione, esploreranno varie tattiche, tecniche e procedure (TTP) associate al Lazarus Group.
author: dua2z3rr
date: 2025-10-26 1:00:00
categories: Sherlocks
tags: []
---

## Introduzione

### Domande

1.  Chi ha condotto l'Operazione Dream Job?
2.  Quando è stata osservata per la prima volta questa operazione?
3.  Ci sono 2 campagne associate all'Operazione Dream Job. Una è Operation North Star, qual è l'altra?
4.  Durante l'Operazione Dream Job, sono stati utilizzati due binari di sistema per l'esecuzione proxy. Uno era Regsvr32, qual era l'altro?
5.  Quale tecnica di movimento laterale ha utilizzato l'avversario?
6.  Qual è l'ID della tecnica per la risposta precedente?
7.  Quale Trojan di Accesso Remoto ha utilizzato il Lazarus Group nell'Operazione Dream Job?
8.  Quale tecnica ha utilizzato il malware per l'esecuzione?
9.  Quale tecnica ha utilizzato il malware per evitare il rilevamento in una sandbox?
10. Per rispondere alle domande rimanenti, utilizza VirusTotal e fai riferimento al file IOCs.txt. Qual è il nome associato al primo hash fornito nel file IOC?
11. Quando è stato creato il file associato al secondo hash nell'IOC?
12. Qual è il nome del file di esecuzione padre associato al secondo hash nell'IOC?
13. Esamina il terzo hash fornito. Qual è il nome del file probabilmente utilizzato nella campagna che si allinea con le tattiche note dell'avversario?
14. Quale URL è stato contattato in data 2022-08-03 dal file associato al terzo hash nel file IOC?

### Overview

Nella cartella compressa ricevuta per completare lo sherlock abbiamo 3 hash che dovremmo scannerizare con **VirusTotal**. Per il resto dello sherlock, delle ricerche web tramite il **framework MITRE ATT&CK** saranno sufficienti.

## Risposte

### Chi ha condotto l'Operazione Dream Job?

Cerchiamo sul MITRE ATT&CK framework l'operazione **Dream Job**.

![Desktop View](/assets/img/dream-job-1/dream-job-1-1.png)

Risposta: `Lazarus Group`

### Quando è stata osservata per la prima volta questa operazione?

Troviamo la risposta sulla parte destra della pagina che abbiamo trovato per risposndere alla domanda di prima.

![Desktop View](/assets/img/dream-job-1/dream-job-1-2.png)

Risposta: `September 2019`

### Ci sono 2 campagne associate all'Operazione Dream Job. Una è Operation North Star, qual è l'altra?

La risposta si trova sotto al campo per la risposta precedente.

Risposta: `Operation Interception`

### Durante l'Operazione Dream Job, sono stati utilizzati due binari di sistema per l'esecuzione proxy. Uno era Regsvr32, qual era l'altro?

Se utilizziamo la shortcut `Ctrl + F` per cercare parole utilizzate all'interno della pagina. Cerchiamo Regsvr32 e troviamo la risposta accanto.

![Desktop View](/assets/img/dream-job-1/dream-job-1-3.png)

Risposta: `Rundll32`

### Quale tecnica di movimento laterale ha utilizzato l'avversario?

Filtrando le tecniche di lateral movement nell'**ATT&CK Navigator**, Troviamo la risposta.

![Desktop View](/assets/img/dream-job-1/dream-job-1-4.png)

Risposta: `Internal Spearphishing`

### Qual è l'ID della tecnica per la risposta precedente?

Mettendo il cursore sopra la casella azzurra trovata precedentemente, possiamo trovare l'ID della tecnica usata dagli attaccanti.

![Desktop View](/assets/img/dream-job-1/dream-job-1-5.png)

Risposta: `T1534`

### Quale Trojan di Accesso Remoto ha utilizzato il Lazarus Group nell'Operazione Dream Job?

Andando in fondo alla pagina iniziale del MITRE ATT&CK framework, possiamo vedere che durante l'operazione sono stati utilizzati 3 software. Se ispezioniamo il primo, troviamo la risposta che stiamo cercando.

![Desktop View](/assets/img/dream-job-1/dream-job-1-6.png)

Risposta: `DRATzarus`

### Quale tecnica ha utilizzato il malware per l'esecuzione?

Possiamo cercare la risposta andando sull'**ATT&CK Navigator** del virus e la troveremo sotto la colonna **Execution**.

Risposta: `Native API`

### Quale tecnica ha utilizzato il malware per evitare il rilevamento in una sandbox?

Ripetiamo il procedimento che abbiamo utilizzato nella domanda precedente. La risposta si trova nella sezione **Defense Evasion**.

Risposta: `Time Based Evasion`

### Per rispondere alle domande rimanenti, utilizza VirusTotal e fai riferimento al file IOCs.txt. Qual è il nome associato al primo hash fornito nel file IOC?

Inseriamo l'hash nella gui di VirusTotal e troviamo la risposta nell'output.

![Desktop View](/assets/img/dream-job-1/dream-job-1-8.png)

Risposta: `IEXPLORE.exe`

### Quando è stato creato il file associato al secondo hash nell'IOC?

Inseriamo il secondo hash nel file di testo e leggiamo la sezione **DETAILS**.

![Desktop View](/assets/img/dream-job-1/dream-job-1-9.png)

Risposta: `2020-05-12 19:26:17`

### Qual è il nome del file di esecuzione padre associato al secondo hash nell'IOC?

La risposta si trova nella sezione **RELATIONS**.

Risposta: `BAE_HPC_SE.iso`

### Esamina il terzo hash fornito. Qual è il nome del file probabilmente utilizzato nella campagna che si allinea con le tattiche note dell'avversario?

Troviamo la risposta nella sezione **DETAILS** sotto **Names**.

Risposta: `Salary_Lockheed_Martin_job_opportunities_confidential.doc`

### Quale URL è stato contattato in data 2022-08-03 dal file associato al terzo hash nel file IOC?

Troviamo la soluzione nella sezione **RELATIONS** sotto **Contacted URLs**.

Risposta: `https://markettrendingcenter.com/lk_job_oppor.docx`
