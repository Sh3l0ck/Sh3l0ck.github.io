---
layout: post
title: The Kolona Virus
date: '2024-05-14 00:00:00 +0000'
categories: [WriteUps]
tags: [skrctf, reverse engineering]  
---

# Challenge

OMG! My picture is corrupted with the Kolona virus! I managed to get the virus source code and the corrupted picture, please help me recover it. I will give you a flag for a reward!

**Difficulty:** Medium

## Solution

First, to begin, I downloaded 2 files: a zip file ([The Kolona Virus](/assets/img/TheKolonaVirus/The_Kolona_Virus.zip)) and the corrupted img file ([kolonaFlag](/assets/img/TheKolonaVirus/flag.kolona)). Once downloaded and unzipped the zip file I got 3 files: `kolona_virus`, `MN908947`, and `spread_kolona.py`.

The hint in SKR CTF you will get "Have you tried to "print" the virus?". So following these wise words, I just played around with the Python file, changed the last `exec()` command to a `print()` to print the virus.

Here I get:
```python
└─$ python spread_kolona.py
flag = open("flag.jpg","r")
kolona = open("flag.kolona","w+")
key = "COVID-19"

for i,c in enumerate(flag.read()):
        kolona.write(chr(ord(c) ^ ord(key[i % len(key)])))

```

From here I just created a new Python file called flag.py, copied pasted the code, and saved it, and then ran it. Only to end up with an error...
```python
└─$ sudo python flag.py 
Traceback (most recent call last):
  File "/home/kali/Downloads/flag.py", line 5, in <module>
    for i,c in enumerate(flag.read()):
                         ^^^^^^^^^^^
  File "<frozen codecs>", line 322, in decode
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xbc in position 0: invalid start byte
```

After searching online for a bit, I have come across a solution on Stack Overflow. It seems that you cannot use "r" and "w" on JPGs without errors, so after changing that and rewriting the code, I finally get the uncorrupted image.

![flag](/assets/img/TheKolonaVirus/flag.jpg)


**Flag:** SKR{V1rus_1s_3verywhere_pl3453_st4y_4t_H0me}

Habis!!!
