---
title: "PhishNet Walkthrough"
description: "In questo Sherlock molto facile, ti familiarizzerai con i log Unix auth.log e wtmp. Esploreremo uno scenario in cui un server Confluence è stato compromesso tramite brute-force sul servizio SSH. Dopo aver ottenuto l’accesso, l’attaccante ha svolto ulteriori attività rilevabili tramite auth.log. Anche se auth.log viene usato principalmente per l’analisi dei brute-force, andremo a sfruttare tutto il suo potenziale nell’indagine, inclusi aspetti di privilege escalation, persistenza e persino visibilità sull’esecuzione di comandi."
author: dua2z3rr
date: 2025-09-30 1:00:00
categories: [Sherlocks]
tags: []
---

## Introduzione

### Domande

1. Qual è l'indirizzo IP di origine del mittente?
2. Quale server di posta ha inoltrato questa email prima che raggiungesse la vittima?
3. Qual è l'indirizzo email del mittente?
4. Qual è l'indirizzo email specificato nel campo "Reply-To" dell'email?
5. Qual è il risultato della verifica SPF (Sender Policy Framework) per questa email?
6. Quale dominio è utilizzato nell'URL di phishing all'interno dell'email?
7. Qual è il nome dell'azienda fasulla utilizzata nell'email?
8. Qual è il nome dell'allegato incluso nell'email?
9. Qual è l'hash SHA-256 dell'allegato?
10. Qual è il nome del file malevolo contenuto all'interno dell'allegato ZIP?
11. Quali tecniche MITRE ATT&CK sono associate a questo attacco?

### Overview

In questo sherlock lavoreremo solo con un unico file
