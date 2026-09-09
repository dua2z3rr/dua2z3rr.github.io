---
title: Computational Recruiting - HTB Very Easy Misc Challenge | Scripted Candidate Scoring and Ranking
description: Complete walkthrough of Computational Recruiting from Hack The Box. A very easy misc challenge where a remote service provides a data.txt file of 200 candidates with six skills each and asks for the top 14 ranked by a weighted overall value. The provided formulas are reimplemented in Python (respecting Python 3's banker's rounding) to parse the file, compute each candidate's score, and sort them. pwntools is then used to submit the top 14 to the service and retrieve the flag.
author: dua2z3rr
date: 2026-09-09 2:00:00
categories:
  - Challenges
  - HackTheBox
tags:
  - misc
---

## Challenge Overview

Not too long ago, your cyborg detective friend John Love told you he heard some strange rumours from some folks in the Establishment that he's searching into. They talked about the possible discovery of a new vault, vault 79, which might hold a big reserve of gold. Hearing of these news, youband your fellow compatriots slowly realized that with that gold reserver you could accomplish your dreams of reviving the currency of old times, and help modern civilization flourish once more. Looking at the potential location of the vault however, you begin to understand that this will be no easy task. Your team by itself is not enough. You will need some new recruitments. Now, standing in the center of Gigatron, talking and inspiring potential recruits, you have collected a big list of candidates based on skills you believe are needed for this quest. How can you decide however which ones are truly worthy of joining you?

---

## Solution

### What We're Given

The challenge provides us with an IP, to which if we connect we get a message (visible below) telling us what to submit to obtain the flag, and a data.txt file.

Let's read the file first:

```
============ ============== ======== ========= ========== =========== ======== =================    
 First Name    Last Name     Health   Agility   Charisma   Knowledge   Energy   Resourcefulness     
============ ============== ======== ========= ========== =========== ======== =================    
 Alis         Reeson              2         5          5           8        7                10     
 Gerri        Bielfelt            8         9          3           8        5                 9     
 Wolfie       Appleby             5         1          2           7        2                 1     
 Krishnah     Minker              1         7          7          10        6                 5     
 Cassondra    Peizer              9         8          8           2        6                 4     
 Jamie        Aston              10         7          4           1        5                 9     
 Hester       Ditty               7         5          4           4        9                 8     
 Shay         Sheardown          10         8          6           3        2                10     
 Philomena    Ellesworth          1         4          4           6        2                 2     

<SNIP>

 Scotti       Manuele             6         8          5           9        9                 6     
 Consolata    Sleightholm         1         4          9           9        2                 2     
 Ashlan       Clearie             1         4          8          10        4                 7     
 Joanna       Brody               7        10          7           3        6                 3     
 Judie        Bushill             4         5          9           9        4                10     
 Debor        Jullian             7         8          1           1        3                 8     
 Rusty        Ardern             10        10          2          10        6                 1     
 Nikaniki     Overall             3         6          7           7        6                 5     
============ ============== ======== ========= ========== =========== ======== ================= 
```

It looks like a list of candidates and the points of each stat, very similar to the game **Fallout 4**. Let's read what the challenge asks us when we connect via netcat to the IP.

```
nc 154.57.164.82 31285             
You will be given a file with N = 200 different potential candidates. Every candidates has 6 different skills, with a score 1 <= s <= 10 for each.  
The formulas to calculate their general value are:  
       <skill>_score = round(6 * (int(s) * <skill>_weight)) + 10  
       overall_value = round(5 * ((health * 0.18) + (agility * 0.20) + (charisma * 0.21) + (knowledge * 0.08) + (energy * 0.17) + (resourcefulness * 0.16)))  
       Note: The round() function here is Python 3's round(), which uses a concept called Banker's Rounding  
The weights for the 6 skills are: health_weight = 0.2, agility_weight = 0.3, charisma_weight = 0.1, knowledge_weight = 0.05, energy_weight = 0.05, resourcefulness_weight = 0.3  
Enter the first 14 candidates ordered in the highest overall values.  
Enter them like so: Name_1 Surname_1 - score_1, Name_2 Surname_2 - score_2, ..., Name_i Surname_i - score_i  
       e.g. Timothy Pempleton - 94, Jimmy Jones - 92, Randolf Ray - 92, ...  
>
```

Good, using the data provided by the file we have to calculate the points of the various skills, then the `overall_value`, and finally sort the candidates and take the best 14.

### Scripting

We'll use Python as the language. Let's start by creating 3 functions to make the code a bit cleaner.

```python
people = gather_data()
people = sum_of_stats(people)
send_data(people)
```

We create the `gather_data()` function which will serve to parse the `data.txt` file.

```python
def gather_data():
    res = []
    with open ('data.txt', 'r') as data:
        for index, line in enumerate(data):
            if index > 3 and index < 204:
                res.append(line.strip())

    for index, record in enumerate(res):
        record = " ".join(record.split())
        record = record.split(' ')
        res[index] = record

    return res
```

The result will be this:

```python
[['Alis', 'Reeson', '2', '5', '5', '8', '7', '10'], ['Gerri', 'Bielfelt', '8', '9', '3', '8', '5', '9'], ['Wolfie', 'Appleby', '5', '1', '2', '7', '2', '1'], <SNIP>
```

Now we create the **sum_of_stats()** function, which will do the calculations needed for the sorting, and finally the actual sorting. To each candidate a variable will be added that will be the overall score, and the sorting will be done on that.

```python
def sum_of_stats(people):
    for person in people:
        health = round(6 * (int(person[2]) * 0.2)) + 10
        agility = round(6 * (int(person[3]) * 0.3)) + 10
        charisma = round(6 * (int(person[4]) * 0.1)) + 10
        knowledge = round(6 * (int(person[5]) * 0.05)) + 10
        energy = round(6 * (int(person[6]) * 0.05)) + 10
        resourcefulness = round(6 * (int(person[7]) * 0.3)) + 10
        tot = round(5 * ((health * 0.18) + (agility * 0.20) + (charisma * 0.21) + (knowledge * 0.08) + (energy * 0.17) + (resourcefulness * 0.16)))
        person.append(tot)

    people = sorted(people, key=lambda x: x[8], reverse=True)

    return people
```

The result will be this:

```python
[['Jayson', 'Enderby', '8', '10', '10', '1', '1', '10', 98], ['Malva', 'Shreeve', '10', '9', '3', '5', '7', '10', 96], ['Randolf', 'Raybould', '10', '10', '3', '6', '6', '9', 96], ['Shay', 'Sheardown', '10', '8', '6', '3', '2', '10', 95], ['Koo', 'Rue', '8', '7', '8', '6', '8', '10', 94], ['Tabina', 'Nathon', '7', '8', '10', '1', '8', '10', 94], ['Taber', 'Haile', '9', '7', '10', '8', '1', '9', 93], ['Constanta', 'Rolfs', '10', '6', '5', '8', '9', '10', 93], <SNIP>
```

Finally we submit the best fourteen candidates as requested to the challenge's IP in the `send_data(people)` function. We also have to import pwntools.

```python
from pwn import *  # pyright: ignore[reportWildcardImportFromLibrary]

<SNIP>

def send_data(people):
    conn = remote('154.57.164.82', 32482)
    conn.recvuntil('Randolf Ray - 92, ...\n> ')
    answer = ''
    
    for index in range(14):
        answer += people[index][0] + ' ' + people[index][1] + ' - ' + str(people[index][8])
        if index != 13:
            answer += ', '
    
    conn.sendline(answer.encode('utf-8'))
    flag = conn.recv()
    print(flag)
```

We submit the data and obtain the flag.

**Flag obtained.**
