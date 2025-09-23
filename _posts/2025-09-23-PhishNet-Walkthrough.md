---
title: "PhishNet Walkthrough"
description: "Un team di contabilità riceve una richiesta di pagamento urgente da un fornitore conosciuto. L'email appare legittima ma contiene un link sospetto e un allegato .zip che nasconde malware. Il tuo compito è analizzare le intestazioni dell'email e scoprire lo schema dell'attaccante."
author: dua2z3rr
date: 2025-09-23 1:00:00
categories: Sherlocks
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

IL materiale di questo sherlock è un singolo file. Questo file si chiama "**email.eml**" ed è la email di phishing che oggi dovremmo analizzare per rispondere alle domande. Essendo il file piccolo, è stato riportato qua sotto:

```eml
Return-Path: <finance@business-finance.com>
Reply-To: <support@business-finance.com>
X-Mailer: Microsoft Outlook 16.0
X-Originating-IP: [45.67.89.10]
X-Priority: 1 (Highest)
X-MSMail-Priority: High
Received-SPF: Pass (protection.outlook.com: domain of business-finance.com designates 45.67.89.10 as permitted sender)
ARC-Seal: i=1; a=rsa-sha256; d=business-finance.com; s=arc-2025; t=1677416100; cv=pass;
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=business-finance.com; s=arc-2025;
X-AntiSpam: Passed
X-Organization: Business Finance Ltd.
X-Envelope-From: finance@business-finance.com
List-Unsubscribe: <mailto:unsubscribe@business-finance.com>
X-Sender-IP: 45.67.89.10
Received: from mail.business-finance.com ([203.0.113.25])
	by mail.target.com (Postfix) with ESMTP id ABC123;
	Mon, 26 Feb 2025 10:15:00 +0000 (UTC)
Received: from relay.business-finance.com ([198.51.100.45])
	by mail.business-finance.com with ESMTP id DEF456;
	Mon, 26 Feb 2025 10:10:00 +0000 (UTC)
Received: from finance@business-finance.com ([198.51.100.75])
	by relay.business-finance.com with ESMTP id GHI789;
	Mon, 26 Feb 2025 10:05:00 +0000 (UTC)
Authentication-Results: spf=pass (domain business-finance.com designates 45.67.89.10 as permitted sender)
	 smtp.mailfrom=business-finance.com;
	 dkim=pass header.d=business-finance.com;
	 dmarc=pass action=none header.from=business-finance.com;
Message-ID: <20250226101500.ABC123@business-finance.com>
Date: Mon, 26 Feb 2025 10:15:00 +0000 (UTC)
From: "Finance Dept" <finance@business-finance.com>
To: "Accounting Dept" <accounts@globalaccounting.com>
Subject: Urgent: Invoice Payment Required - Overdue Notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html>
<head>
  <title>Invoice Overdue</title>
</head>
<body>
  <p>Dear Accounting Team,</p>
<p>This is a final notice regarding the outstanding invoice #INV-2025-0012. Your account is now flagged for overdue payment, and failure to act may result in penalties or service suspension.</p>
<p>Details of the invoice:</p>
<ul>
  <li><b>Invoice Number:</b> INV-2025-0012</li>
  <li><b>Amount Due:</b> $4,750.00</li>
  <li><b>Due Date:</b> February 28, 2025</li>
</ul>
  <p>Our records indicate that invoice #INV-2025-0012 is overdue for payment. Please process the payment immediately to avoid late fees.</p>
  <p>For your convenience, you can download the full invoice and payment instructions from the link below:</p>
  <p><a href="https://secure.business-finance.com/invoice/details/view/INV2025-0987/payment">Download Invoice</a></p>
  <p>Alternatively, the invoice is also attached as a .zip file.</p>
  <p>If you have already made the payment, kindly ignore this notice.</p>
  <p>Best regards,<br>Finance Department<br>Business Finance Ltd.</p>
</body><p>For assistance, please contact our support team at <a href='mailto:support@business-finance.com'>support@business-finance.com</a> or call our helpline at +1-800-555-0199.</p>
<p>Thank you for your prompt attention to this matter.</p>

</html>

--boundary123
Content-Type: application/zip; name="Invoice_2025_Payment.zip"
Content-Disposition: attachment; filename="Invoice_2025_Payment.zip"
Content-Transfer-Encoding: base64

UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7

--boundary123--
```

Analizziamolo dall'inizio:

Nelle prime 15 righe (circa) vediamo le informazioni generali che servono per l'invio della mail: sender, SPF, priority, ecc.

Dopo le prime 15 righe ci troviamo davanti al percorso che la mail ha fatto per raggiungere il destinatario. ha infatti percorso 3 domini / sottodomini per arrivare a destinazione.

Infine ci troviamo il contenuto della email in formato html. La prima cosa che saltà all'occhio è un link al centro della mail. Questo url fa scaricare la zip in fondo al file, che al momento è transformata dall'encoding base64.

## Risposte

### Qual è l'indirizzo IP di origine del mittente?

Per rispondere a questa domanda ci basta leggere il campo **X-Originating-IP** all'inizio del file.

Risposta: `45.67.89.10`

### Quale server di posta ha inoltrato questa email prima che raggiungesse la vittima?

Guardando solo i nomi dei domini che la mail ha attraversato non riusciremmo a capire l'ordine che è stato percorso. Penseremmo probabilmente che l'ultimo server che ha inoltrato la mail è quello in fondo. Invece, guardando le date in cui la mail ha raggiunto ciascun server, vedfiamo che l'ultimo è quello in cima, **mail.business-finance.com**.

Risposta: `203.0.113.25`

### Qual è l'indirizzo email del mittente?

Leggiamo gli headers della mail per trovare il campo **From:**.

Risposta: `finance@business-finance.com`

### Qual è l'indirizzo email specificato nel campo "Reply-To" dell'email?

Leggiamo il campo **Replay-To**.

Risposta: `support@business-finance.com`

### Qual è il risultato della verifica SPF (Sender Policy Framework) per questa email?

Leggiamo il campo **Received-SPF** all'inizio del file.

Risposta: `PASS`

### Quale dominio è utilizzato nell'URL di phishing all'interno dell'email?

Leggiamo il dominio all'interno del link che l'attaccante ha inviato all'interno il corpo della email.

Risposta: `secure.business-finance.com`

### Qual è il nome dell'azienda fasulla utilizzata nell'email?

Leggiamo la mail e troviamo riferimenti a una azienda.

Risposta: `Business Finance Ltd.`

### Qual è il nome dell'allegato incluso nell'email?

Leggiamo la fine della mail dove sono scritti tutti i campi del file.

Risposta: `Invoice_2025_Payment.zip`

### Qual è l'hash SHA-256 dell'allegato?

Per ottenere la risposta, dobbiamo copiare la stringa in base64 in fondo la mail e aprire il terminale. Poi, usare questo comando:

```shell
echo "UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7" | base64 -d | sha256sum
```

Risposta: `8379C41239E9AF845B2AB6C27A7509AE8804D7D73E455C800A551B22BA25BB4A`

### Qual è il nome del file malevolo contenuto all'interno dell'allegato ZIP?

Per ottenere questa risposta dobbiamo togliere  il comando `sha256sum` dal comando della domanda precedente.

```shell
echo "UEsDBBQAAAAIABh/WloXPY4qcxITALvMGQAYAAAAaW52b2ljZV9kb2N1bWVudC5wZGYuYmF0zL3ZzuzIsR18LQN+h62DPujWX0e7" | base64 -d
PZZ=�*s��invoice_document.pdf.bat̽���ȱ|-~���>��_G�
```

Vediamo il nome di un file all'interno dell'output.

Risposta: `invoice_document.pdf.bat`

### Quali tecniche MITRE ATT&CK sono associate a questo attacco?

Facciamo questa ricerca online: **MITRE ATT&CK technique phishing**

![Desktop View](/assets/img/phishnet/phishnet-mitre.png)

Noi abbiamo ricevuto un file malevolo attraverso l'attachment.

Risposta: `T1566.001`

