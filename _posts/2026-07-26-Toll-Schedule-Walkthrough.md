---
title: "Toll Schedule - HTB Easy Coding Challenge | Greedy Minimum-Wait Assignment"
description: "Walkthrough for the Toll Schedule challenge from Hack The Box. An easy coding challenge where convoys with known arrival times must each be seated at a distinct clearance opening no earlier than their arrival, minimizing the total wait. Sorting both lists and greedily assigning each convoy the earliest still-available clearance yields the optimal total."
author: dua2z3rr
date: 2026-07-26 2:00:00
categories:
  - CTF Competitions
  - Challenges
  - HackTheBox
  - "Cyber Apocalypse CTF 2026: The Salt Crown"
tags:
  - coding
---

## Challenge Overview

Stonepass doesn't close for weather anymore. It closes on words borrowed from weather — "raiders," "avalanches," "public order" — while the schedule underneath keeps quietly playing favourites: one banner's convoys glide through, another's stack up in the snow until daylight dies. Elric Ashspar has spent weeks sketching the checkpoint's hardware and is certain of one thing — the mechanism isn't broken. It's tuned. To prove it, Elric first needs the number nobody at the gate wants published: the least total time this exact column of convoys could possibly spend waiting, under any legal assignment of clearances to convoys. Each convoy reaches the pass at a known time; each clearance opens at a known time and can seat exactly one convoy, no earlier than its arrival. Elric must find the assignment that minimises the column's total wait — the clean baseline the real schedule will be measured against.

---

## Solution

### Challenge Web Page

As with every coding challenge, we're given a browser IDE where we can test our code:

![browser ide](assets/img/toll-schedule/ide.png)

### Understanding the Problem

The program reads its data from standard input across three lines:

- The first line contains two numbers: the count of convoy arrival times and the count of clearance opening times.
- The second line contains the arrival times of the convoys (**N**).
- The third line contains the opening times of the clearances (**G**).

Each clearance can seat exactly one convoy, and only at a time no earlier than that convoy's arrival. A convoy assigned to a clearance that opens at time `t` waits for `t - arrival`. Our goal is to find the assignment of clearances to convoys that minimizes the **total** wait across the whole column.

The optimal strategy is greedy. If we sort both the arrival times and the opening times in ascending order, then process convoys from the earliest arrival to the latest and give each one the earliest still-available clearance that opens at or after its arrival, we obtain the minimum total wait. Removing a clearance from the pool once it's used guarantees a one-to-one assignment.

### Final Code

Here's the final code. Below is the explanation of each step.

```python
first_input = input()

# read arrival times (N)

N = input().split(' ')
N = [int(x) for x in N]
N.sort()

# read opening times (G)

G = input().split(' ')
G = [int(x) for x in G]
G.sort()

# calculate total time

total_time = 0

for arrival in N:
	for opening in G:
		if opening >= arrival:
			total_time += opening - arrival
			G.remove(opening)
			break

print(total_time)
```

### Step One: Reading the First Input

The first step is to read the first line of the input, which is the number of elements in the second line and the number of elements in the third line.

```python
first_input = input()
```

We don't need to store this information, since it can be derived from the other inputs.

### Step Two: Building the N List

We create a list of strings, each containing one N value. Then we convert each string into an integer and sort them, since they're provided unordered.

```python
# read arrival times (N)

N = input().split(' ')
N = [int(x) for x in N]
N.sort()
```

### Step Three: Building the G List

Exactly the same as for N, but for G.

```python
# read opening times (G)

G = input().split(' ')
G = [int(x) for x in G]
G.sort()
```

### Calculating the Total Time

We can calculate the total time with two nested for loops. It's important to remove the G element with **G.remove()**, since a G can only be assigned to a single N.

```python
# calculate total time

total_time = 0

for arrival in N:
	for opening in G:
		if opening >= arrival:
			total_time += opening - arrival
			G.remove(opening)
			break

print(total_time)
```
