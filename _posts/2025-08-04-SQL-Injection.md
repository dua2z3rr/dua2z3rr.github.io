---
title: "SQL Injection: La falla che ha cambiato la cybersecurity"
description: "Dai primi attacchi devastanti alle moderne difese: come una vulnerabilità apparentemente semplice ha costretto la cybersecurity a reinventarsi, cambiando per sempre il rapporto tra sviluppo e sicurezza."
author: dua2z3rr
date: 2025-08-04 2:00:00
categories: [Approfondimenti]
tags: ["Approfondimento: Web Security", "Approfondimento: Database", "Approfondimento: Vulnerability Research"]
---

![Desktop View](/assets/img/SQL_Injection/d5d3890b-164e-406b-92a0-f0d8121faafa.png)

## Introduzione

`"Presentava tutte le caratteristiche di un attacco SQL-injection, e ne aveva uno preferito. Nei campi di logon e password inserì: ‘or 1=1--"`

### La scoperta della vulnerabilità

Jeff Forristal, aka. "Rain Forest Puppy", è stato una delle prime persone a mai documentare una SQL Injection. Adesso il CTO della Bluebox Security, scrisse il suo primo articolo a riguardo nel 1998.

Subito dopo la pubblicazione della sua scoperta, molti hacker (sia buoni che cattivi) sperimentarono con questo nuovo genere di vulnerabilità. Non ci volle molto per la nascita di molti tipi di SQL injections, tra cui SQLi2RCE.

> SQLi2RCE è un tipo di SQL injction che ci permette di eseguire codice sul server che ospita il database. è una, se non la più, pericolosa sql injection ed è quella che viene pagata di più nelle bug bounty.
{: .prompt-warning }

### L'impatto iniziale sul mondo della cybersecurity

Durante il primo anno dopo l'uscita dell'articolo, vennero compromesse molte zone amministrative. Questo mise in allera gli sviluppatori, che dovettero patchare in autonomia questa vulnerabilità visto che Microsoft non pubblicò alcuna patch.

## Anatomia di una SQL Injection

SQL (Structured Query Language) è un linguaggio specialmente realizzato per la realizzazione e gestione di database.

Al giorno d'oggi, i database sono ovunque: da applicazioni di piccola scala a enormi aziende. Inoltre, esistono molti SQL databases, ognuno con i suoi pro e contro: MySQL, PostgreSQL, Oracle Database, Microsoft SQL Server. 

Una SQL Injection è un tipo di attacco che sfrutta le vulnerabilità in applicazioni web e database SQL.

### Cosa succede dietro le quinte (meccanismo base)

Le SQL Injection si basano su comandi SQL con degli input che l'utente può inserire.

```sql
SELECT * FROM users WHERE username = '[username]' AND password = '[password]'
```

In questo caso, è possibile sostituire le variabili username e password, e se l'input non viene sterilizzato, possiamo inserire comandi SQL. Un classico esempio sarebbe `‘ OR 1=1 —`, il quale ci permetterebbe di accedere visto che la condizione è sempre vera (1 è sempre uguale a 1).

### Tipologie Principali

1. In-Band (Classica)
  Attacchi dove l'attacco e i risultati di esso sono comunicati tramite lo stesso canale.
2. Blind
  Nessun dato diretto è restituito, ma sta all'attaccante interpretare la risposta.
3. Time-Based Blind
  Sottotipo delle blind, l'attaccante mette dei delay nelle richieste per capire se la iniezione ha avuto successo o meno.
4. Error-Based
  Attraverso delle iniezioni che mirano a generare errori si può comprendere la struttura del database.
5. Union-Based
  Per prima cosa si tenta a indovinare il numero di colonne in una tabella. poi, quando si ha il numero esatto, si uniscono più comandi `SELECT` per ottenere un grande numero di informazioni.
6. Out-Of-Band
  iniezioni che vengono utilizzate se il database è configurato a bloccare risposte dirette (non possiamo ottenere dati utilizzando lo stesso canale in cui iniettiamo il codice). Possiamo utilizzare il canale HTTP e DNS per ottenere dati dai database.
7. Second-Order
  L'iniezione inserisce un payload in un campo che lo salverà all'interno del database, dando accesso non autorizzato agli attaccanti o manipolare dati. 

### Esempi pratici di codice vulnerabile vs sicuro

#### PHP (MySQLi)

Versione vulnerabile (`' OR '1'='1` come username):

```php
<?php
$username = $_POST['username']; // Input non validato dall'utente
$password = $_POST['password']; // Input non validato

$conn = new mysqli("localhost", "user", "pass", "db");
if ($conn->connect_error) die("Connessione fallita");

// 🚨 PERICOLO: Concatenazione diretta nella query
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query);

if ($result->num_rows > 0) {
    echo "Accesso consentito!";
} else {
    echo "Credenziali errate!";
}
$conn->close();
?>
```

Versione sicura (prepared statements):

```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];

$conn = new mysqli("localhost", "user", "pass", "db");
if ($conn->connect_error) die("Connessione fallita");

// ✅ SICURO: Query parametrizzata con bind_param
$query = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("ss", $username, $password); // "ss" = due stringhe
$stmt->execute();

$result = $stmt->get_result();
if ($result->num_rows > 0) {
    echo "Accesso consentito!";
} else {
    echo "Credenziali errate!";
}

$stmt->close();
$conn->close();
?>
```

#### Python (SQLite)

Versione vulnerabile (`' OR 1=1` invalida la autenticazione):

```python
import sqlite3

username = input("Username: ")  # Input non validato
password = input("Password: ")  # Input non validato

conn = sqlite3.connect("mydb.db")
cursor = conn.cursor()

# 🚨 PERICOLO: Concatenazione diretta nella query
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)

if cursor.fetchone():
    print("Accesso consentito!")
else:
    print("Credenziali errate!")

conn.close()
```

Versione sicura (query parametizzate):

```python
import sqlite3

username = input("Username: ")
password = input("Password: ")

conn = sqlite3.connect("mydb.db")
cursor = conn.cursor()

# ✅ SICURO: Placeholder e tupla di parametri
query = "SELECT * FROM users WHERE username = ? AND password = ?"
cursor.execute(query, (username, password))  # Dati passati separatamente

if cursor.fetchone():
    print("Accesso consentito!")
else:
    print("Credenziali errate!")

conn.close()
```

#### Node.js (mysql2)

Versione vulnerabile:

```js
const mysql = require('mysql2');
const connection = mysql.createConnection({ /* credenziali */ });

const username = req.body.username; // Input non validato
const password = req.body.password; // Input non validato

// 🚨 PERICOLO: Template string con input diretto
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
connection.query(query, (err, results) => {
    if (err) throw err;
    
    if (results.length > 0) {
        console.log("Accesso consentito!");
    } else {
        console.log("Credenziali errate!");
    }
});
```
Versione sicura (prepared statements):

```js
const mysql = require('mysql2');
const connection = mysql.createConnection({ /* credenziali */ });

const username = req.body.username;
const password = req.body.password;

// ✅ SICURO: Placeholder e valori separati
const query = "SELECT * FROM users WHERE username = ? AND password = ?";
connection.execute(query, [username, password], (err, results) => {
    if (err) throw err;
    
    if (results.length > 0) {
        console.log("Accesso consentito!");
    } else {
        console.log("Credenziali errate!");
    }
});
```

## Punti di svolta storici

### Attacco famoso 

Nel 2017, Equifax, una delle principali agenzie di credito statunitensi, subì un devastante attacco SQL injection-based che compromise i dati personali di 143 milioni di persone. Gli hacker sfruttarono una vulnerabilità nel framework Apache Struts utilizzato nel portale web "Dispute Resolution", iniettando codice SQL malevolo per accedere a database.

Aggravante fu il fatto che Equifax era stata avvisata mesi prima da ricercatori di sicurezza sulla presenza di SQLi nel sistema, ma non aveva applicato le patch necessarie 9.

Gli hacker usarono l'operatore `UNION` per unire query legittime a comandi dannosi, estraendo dati da tabelle non correlate.

esempio di payload:

```sql
' UNION SELECT credit_card_number, ssn FROM financial_data; --
```

La mancanza di sanitizzazione degli input e di query parametrizzate permise l'esecuzione del codice

### Il costo economico per le aziende colpite

L'attacco precedente ebbe conseguenze finanziarie senza precedenti:

- $700 milioni in multe e risarcimenti (di cui $425 milioni ai colpiti)
- Crollo del 31% nelle settimane successive alla notizia, con una perdita di $4 miliardi in capitalizzazione di mercato.
- Perdita di fiducia dei consumatori e danni reputazionali irreparabili.

Considerando che ogni record rubato valeva $140 sul dark web, gli hacker ricavarono $20 miliardi.

### La nascita degli OWASP Top 10

Gli OWASP Top 10 nacquero nel 2003 come iniziativa dell'Open Web Application Security Project (OWASP), un'organizzazione no-profit dedicata alla sicurezza del software. L'obiettivo era creare un documento di consenso globale per identificare i rischi più critici nelle applicazioni web, basandosi sull'esperienza collettiva di sviluppatori e security expert.

Inizialmente, la selezione delle categorie si basava su sondaggi qualitativi e esperienze soggettive degli esperti. Con gli anni, la metodologia è evoluta verso un approccio ibrido:
- A partire dal 2017, l'80% delle categorie (8 su 10) viene selezionato analizzando dati reali.
- Il 20% rimanente deriva da sondaggi tra professionisti della sicurezza, per includere rischi emergenti non ancora rappresentati nei dataset.
- Nell'edizione 2021, si è passati da categorie sintomatiche (es. Sensitive Data Exposure) a cause profonde (es. Cryptographic Failures).

> Update previsto per fine estate/inizio autunno 2025, con aggiornamenti basati su trend recenti come l'integrità delle supply chain CI/CD.
{: .prompt-info }

## L'evoluzione delle Contromisure

### Prepared Statements e Parameterized Queries

- Separano codice SQL e dati utente, impedendo l'esecuzione di comandi malevoli tramite binding parametrico.
- Trattano gli input come valori letterali, non come codice interpretabile, neutralizzando payload come `' OR 1=1--`.

### Validazione degli input: Whitelist vs Blacklist

- La whitelist autorizza SOLO caratteri/pattern pre-approvati (es. solo numeri per un CAP), eliminando rischi sconosciuti.
- La blacklist (meno sicura) blocca caratteri pericolosi (come ' o ;), ma può essere bypassata con codifiche evasive.

### Ruolo dei Web Application Firewall (WAF)

- Analizzano il traffico HTTP in tempo reale, bloccando richieste con firme SQLi note (es. `UNION SELECT`).
- Funzionano come filtro reattivo complementare, non sostituiscono la sicurezza nel codice ma mitigano attacchi zero-day.

### ORM come strato di protezione aggiuntivo

- Generano query automaticamente tramite metodi (es. `.find()` in Hibernate), evitando concatenamento diretto di stringhe SQL.
- Mappano oggetti su tabelle del DB, introducendo sanitizzazione automatica degli input nei framework come Django ORM o Entity Framework.

## L'Eredità nella Cybersecurity Moderna

### Shift Left Security: prevenire in fase di sviluppo

Integra strumenti come SonarQube o Checkmarx nella pipeline CI/CD per scansionare il codice a ogni Pull Request, flaggando query SQL non parametrizzate. Blocca il merge finché non vengono corretti pattern a rischio (es. `"SELECT * FROM users WHERE id = " + userInput`).

## Conclusioni

### Perchè persiste nonostante le soluzioni

Le SQLi persistono non per mancanza di soluzioni, ma perché:
- Cultura: La sicurezza è vista come un costo, non un abilitatore.
- Complessità: L’evoluzione tecnologica (cloud, microservizi) crea nuovi vettori d’attacco.
- Negligenza: Patch note ma non applicate, come nel caso Equifax.

Il 95% delle SQLi sfrutta vulnerabilità >1 anno vecchie (CISA). La tecnologia esiste, ma senza priorità executive e cultura del secure-by-design, resteremo in un ciclo infinito di violazioni.

### Best practice attuali per sviluppatori

1. Sostituire tutte le query dinamiche con prepared statements.
2. Validare input tramite whitelist per campi non parametrizzabili.
3. Configurare account DB con permessi minimi.
4. Scansione SAST/DAST in pipeline CI/CD.
5. Crittografare dati sensibili a riposo e in transito.
