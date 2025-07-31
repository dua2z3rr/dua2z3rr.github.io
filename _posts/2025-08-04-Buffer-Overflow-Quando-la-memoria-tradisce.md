---
title: "Buffer Overflow: Quando la memoria tradisce"
description: "Deep Dive tecnico sui Buffer Overflow: dalla struttura della memoria a esempi di codice in c."
author: dua2z3rr
date: 2025-08-04 0:00:00
categories: [Approfondimenti]
tags: ["Approfondimento: Binary Exploitation", "Approfondimento: C", "Approfondimento: Memory Management"]
---

## Concetti fondamentali

Un `Buffer Overflow` (o `Buffer Overrun`) è una vulnerabilità di sicurezza critica che si verifica quando un programma scrive dati oltre i limiti di memoria impostati, sovrascrivendo aree adiacenti. Questa condizione può causare crash, corruzione di dati e `esecuzione arbitraria di codice`.

### La terminologia

Un buffer è un'area contigua di memoria allocata per memorizzare dati, mentre un Overflow è un evento che si verifica quando viene scritta una quantità di dati in un buffer maggiore della sua capacità. Per esempio, scrivere 150 byte in un buffer da 100 byte.

### Le cause

Le cause di un buffer overflow sono molte. Le principali sono errori nel codice di un programma e input malformati. Molto spesso, utilizziamo funzioni non sicure che non verificano i limiti del buffer. Alcuni esempi di queste funzioni in C/C++ sono `strcpy`, `gets` e `sprintf`.

```c
#include <string.h>
#include <stdio.h>

int main() {
    char buffer[5];          // Buffer di 5 byte (allocato nello stack)
    char source[] = "Hello, World!";  // 14 byte (13 caratteri + null terminator)

    strcpy(buffer, source);  // Buffer overflow: copia 14 byte in 5

    printf("%s\n", buffer);  // Stampa il buffer (comportamento indefinito)
    return 0;
}
```

## Architettura della Memoria

Ci sono 2 tipi principali di memoria: `Stack` e `Heap`. Dobbiamo comprendere cosa sono se vogliamo capire le varie tipologie di buffer overflow.

> Esiste anche un terzo tipo di area di memoria, la sezione `BSS`. Serve a conservare variabili statiche non inizializzate, tuttavia non la considereremo.
{: .prompt-info }

### Lo Stack (Pila)

Lo Stack memorizza variabili locali, indirizzi di ritorno delle funzioni (`RIP`) parametri, frame pointer (`EBP/RBP`) e cresce verso indirizzi di memoria inferiori.

![Desktop View](/assets/img/Buffer_Overflow/stack.png)

### L'Heap

Mentre lo stack si occupa dell'allocazione statica, l'heap svolge la funzione di area per l'allocazione dinamica. Possiamo salvare una variabile nell'heap grazie alla funzione in C `malloc`:

```c
#include <stdlib.h>

int main() {
    int* ptr = (int*)malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    return 0;
}
```

L'heap è maggiormente utilizzato per strutture dati complesse, come per esempio grandi quantità di memoria con metadati.

## Tipi di Buffer Overflow

Esistono 2 tipi principali di buffer overflow:
1. Stack-Based Overflow
2. Heap-Based Overflow
  
### Stack-Based Overflow

Vengono sovrascritti dati nello stack, come per esempio l'indirizzo di ritorno (`RIP`). L'esempio classico di un buffer overflow è sovrascrivere l'indirizzo di ritorno con uno `shellcode` così che venga eseguito.

> Uno `shellcode` è un piccolo frammento di codice eseguibile spesso scritto in assembly.
{: .prompt-info }

![Desktop View](/assets/img/Buffer_Overflow/before-vs-after-stack.png)

### Heap-Based Overflow

Sfrutta operazioni come `free` o `malloc` per scrivere in aree di memoria arbitrarie.

```c
#include <stdlib.h>
#include <string.h>

int main() {
    // Alloca 5 byte sull'heap
    char *buffer = malloc(5);
    
    // Scrive 10 byte in un buffer da 5 (overflow!)
    strcpy(buffer, "ABCDEFGHI"); // 10 byte (includendo il null-terminator)
    
    // Tentativo di liberare la memoria (crash per corruzione heap)
    free(buffer);
    return 0;
}
```

## Tecniche di Exploitation: Shellcode Injection

```c
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main() {
    // Shellcode per eseguire "/bin/sh" (x86_64, senza byte nulli)
    unsigned char shellcode[] = 
        "\x48\x31\xd2"                              // xor    %rdx, %rdx
        "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"  // mov    $0x68732f6e69622f2f, %rbx
        "\x48\xc1\xeb\x08"                          // shr    $0x8, %rbx
        "\x53"                                      // push   %rbx
        "\x48\x89\xe7"                              // mov    %rsp, %rdi
        "\x50"                                      // push   %rax
        "\x57"                                      // push   %rdi
        "\x48\x89\xe6"                              // mov    %rsp, %rsi
        "\xb0\x3b"                                  // mov    $0x3b, %al
        "\x0f\x05";                                 // syscall

    // Alloca memoria eseguibile con mmap
    void *mem = mmap(
        NULL,
        sizeof(shellcode),
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0
    );

    if (mem == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // Copia lo shellcode nella memoria eseguibile
    memcpy(mem, shellcode, sizeof(shellcode));

    // Cast a funzione e chiamata dello shellcode
    void (*func)() = (void (*)())mem;
    func();

    // Pulizia (non verrà raggiunta se lo shellcode ha successo)
    munmap(mem, sizeof(shellcode));
    return 0;
}
```

1. **Shellcode**:
   - Contiene istruzioni assembly per eseguire `execve("/bin/sh", NULL, NULL)`.
   - È progettato per evitare byte nulli (`\x00`) che potrebbero interrompere l'iniezione.
   - Lunghezza: 23 byte.

2. **Allocazione memoria eseguibile**:
   - `mmap()` alloca una regione di memoria con permessi:
     - `PROT_EXEC`: Memoria eseguibile.
     - `PROT_READ | PROT_WRITE`: Leggibile e scrivibile.
   - `MAP_ANONYMOUS`: La memoria non è associata a nessun file.

3. **Copia dello shellcode**:
   - `memcpy()` copia i byte dello shellcode nella memoria appena allocata.

4. **Esecuzione**:
   - La memoria viene convertita in un puntatore a funzione (`void (*func)()`).
   - Chiamando `func()`, il codice nello shellcode viene eseguito.

## Mitigazioni e Difese

- **Stack Canaries (Stack Cookies)**:  
  - Valore casuale (**canary**) tra buffer e indirizzo di ritorno.  
  - Prima del `ret`, il canary viene verificato. Se modificato, il programma termina.  
  - Tipi: **Terminator canary** (con byte `0x00`), **Random canary**.  
- **NX Bit (No-eXecute) / DEP (Data Execution Prevention)**:  
  - Segmenti di stack e heap contrassegnati come **non eseguibili**.  
  - Previene l'esecuzione di shellcode iniettato.  
- **ASLR (Address Space Layout Randomization)**:  
  - Randomizza gli indirizzi di stack, heap e librerie.  
  - Rende imprevedibili gli indirizzi di funzioni e gadget.  
- **PIE (Position-Independent Executable)**:  
  - Randomizza l'indirizzo base del binario, potenziando l'ASLR.  
- **Safe Coding Practices**:  
  - Sostituire funzioni insicure con versioni sicure (es. `strncpy` invece di `strcpy`, `fgets` invece di `gets`).  
  - Librerie come **libsafe** o strumenti di analisi statica (es. **Coverity**, **Valgrind**).  

## Best Practices

1. Utilizzare linguaggi sicuri come Rust, Go e Java.
2. Integrare strumenti nel CI/CD pipeline.
3. W^X Policy: segmenti di memoria non scrivibili ed eseguibili assieme.
4. Abilitare compiler flags (`-fstack-protector`, `-Wformat-security` in GCC)

## Conclusioni

I buffer overflow restano una minaccia critica nonostante le moderne mitigazioni. Conoscere le sue caratteristiche è importante per scrivere codice sicuro e per la creazione di software robusto.

> Se sei curioso di sapere che conseguenze ha un buffer overflow al giorno d'oggi, cerca online il bug Heartbleed (2014) di OpenSSL.
{: .prompt-danger }
