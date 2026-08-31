---
title: Primed for Action - HTB Very Easy Coding Challenge | Prime Detection via Trial Division
description: Complete walkthrough of Primed for Action from Hack The Box. A very easy coding challenge where an intercepted list of numbers hides exactly two primes among the garbage, and the key is the product of the two. Reading the space-separated list from standard input, testing each value for primality by trial division from 2 up to its rounded square root (skipping anything ≤ 1), and multiplying the two surviving primes directly yields the flag.
author: dua2z3rr
date: 2026-08-31 1:00:00
categories:
  - HackTheBox
  - Challenges
tags:
  - coding
---

## Challenge Overview

Intelligence units have intercepted a list of numbers. They seem to be used in a peculiar way: the adversary seems to be sending a list of numbers, most of which are garbage, but two of which are prime. These 2 prime numbers appear to form a key, which is obtained by multiplying the two. Your answer is the product of the two prime numbers. Find the key and help us solve the case.

---

## Solution

As with every coding challenge, we're given a browser IDE where we can test our code. The problem asks us, given a list of numbers, find the two primes and print the product of the two.

First of all, let's create the list of numbers given as input by the exercise:

```python
n = input()
list_of_numbers = n.split(" ")
print(list_of_numbers)
```

Here's the result for now:

![initial list](assets/img/primed_for_action/initial_list.png)

Now we have to loop through all the numbers and check whether they are prime numbers. Since we know there are only 2, let's create a simple list to put the results in.

To figure out whether a number is prime without using external libraries, we can try dividing it by every number from 2 up to the rounded square root of the number itself. Obviously we have to discard the number if it is equal to or less than 1.

```python
n = input()
list_of_numbers = n.split(" ")
primes = []

for number in list_of_numbers:
    number = int(number)
    if number <= 1:
        continue
    else:
        prime = True
        for divisor in range(2, int(number**0.5)+1):
            if number % divisor == 0:
                prime = False
                break
        if prime:
            primes.append(number)
            
print(primes)
```

With this code we get this output:

![prime list](assets/img/primed_for_action/prime-list.png)

We successfully obtain the 2 prime numbers. Now all that's left is to print the product of the two. Here's the final code that lets us get the flag:

```python
n = input()
list_of_numbers = n.split(" ")
primes = []

for number in list_of_numbers:
    number = int(number)
    if number <= 1:
        continue
    else:
        prime = True
        for divisor in range(2, int(number**0.5)+1):
            if number % divisor == 0:
                prime = False
                break
        if prime:
            primes.append(number)

print(primes[0] * primes[1])
```

**Flag obtained.**
