---
layout: post
title: The Kolona Virus v2
date: '2024-05-15 00:00:00 +0000'
categories: [WriteUps]
tags: [skrctf, reverse engineering]  
---


## Challenge

OMFG!! The virus evolved this time! I only managed to get the virus python compiled file
I have a important file corrupted by the virus, please help me recover it again, I will give you flag for reward!

**Difficulty:** Hard

## Solution

First, to begin, I downloaded the zip file ([Download File](/assets/img/TheKolonaVirusV2/The_Kolona_Virus_2.zip)). Once downloaded and unzipped the zip file I got 5 files: `flag.kolona`, `MT568643`, `spread_kolona.pyc`, `evolved_virus` and `original_virus`.

You'll get 2 hints both of them are useless so ignore them. First thing I did I noticed there was a .pyc and decided might as well decompile it using my favourite decompiler pycdc. 

![emoji](/assets/img/TheKolonaVirusV2/image.png)

(Do note I tried running it and just got error 😔)

```js                                                                          
┌──(kali㉿kali)-[~/Desktop/pycdc]
└─$ ./pycdc /home/kali/Downloads/skrctf/ThekolonaVirusv2/spread_kolona.pyc
# Source Generated with Decompyle++
# File: spread_kolona.pyc (Python 2.7)

kolona_genome = open('MT568643', 'r').read()
kolona_rna = [
    9728,
    9150,
    9459,
    25263,
    1634,
    27368,
    11779,
    19149,
    9629,
    2721]
kolona_rna2 = [
    5676,
    10615,
    13415,
    16286,
    17093,
    13804,
    26647,
    26800,
    4547,
    13208]
original_virus = open('original_virus', 'r').read()
evolve_virus = ''
for i in range(len(original_virus)):
    evolve_virus += chr((ord(original_virus[i]) - ord(kolona_genome[kolona_rna[i % 10]]) - ord(kolona_genome[kolona_rna2[i % 10]])) % 256)

exec evolve_virus
```

I got the above code and immidiately got to fixing it. This script seems to import `MT568643` files and the `evolved_virus` and then using it to output the evolve_virus.

After soem messing around I managed to fix it ended up with the below.

```python
kolona_genome = open('MT568643', 'r').read()
kolona_rna = [
    9728,
    9150,
    9459,
    25263,
    1634,
    27368,
    11779,
    19149,
    9629,
    2721]
kolona_rna2 = [
    5676,
    10615,
    13415,
    16286,
    17093,
    13804,
    26647,
    26800,
    4547,
    13208]
    
with open('original_virus', 'rb') as file:
    original_virus = file.read()

evolve_virus = ''
for i in range(len(original_virus)):
    evolve_virus += chr(
        (original_virus[i] - 
         ord(kolona_genome[kolona_rna[i % 10]]) - 
         ord(kolona_genome[kolona_rna2[i % 10]])) % 256
    )

print(evolve_virus)
```

Run the extracted and fixed python script on terminal

```js
┌──(kali㉿kali)-[~/Downloads/skrctf/ThekolonaVirusv2]
└─$ python spread_kolona.py
kolona_genome = open("MT568643",'r').read()
kolona_rna1 = [23345, 11951, 3108, 5530, 21395, 4536, 27288, 1593, 15001, 3441, 21401, 16319, 3268, 24970, 25483, 26318, 3451, 19165, 23997, 9356]
kolona_rna2 = [26841, 22129, 29143, 13838, 29641, 28796, 11242, 6388, 11659, 19381, 11479, 15576, 25715, 13948, 8014, 6941, 23751, 11716, 22374, 21328]
evolved_virus = open("evolved_virus",'r').read()
code = ""

for i in range(len(evolved_virus)):
        code += chr((ord(evolved_virus[i]) - ord(kolona_genome[kolona_rna1[i % 20]]) - ord(kolona_genome[kolona_rna2[i % 20]])) % 256)

exec(code)
             
```

Fixed the code that was outputted.

```py
kolona_genome = open("MT568643",'r').read()
kolona_rna1 = [23345, 11951, 3108, 5530, 21395, 4536, 27288, 1593, 15001, 3441, 21401, 16319, 3268, 24970, 25483, 26318, 3451, 19165, 23997, 9356]
kolona_rna2 = [26841, 22129, 29143, 13838, 29641, 28796, 11242, 6388, 11659, 19381, 11479, 15576, 25715, 13948, 8014, 6941, 23751, 11716, 22374, 21328]


with open('evolved_virus', 'rb') as file:
    evolved_virus = file.read()




code = ""
for i in range(len(evolved_virus)):
    code += chr(
        (evolved_virus[i] - 
         ord(kolona_genome[kolona_rna1[i % 20]]) - 
         ord(kolona_genome[kolona_rna2[i % 20]])) % 256
    )

print(code)

```

Run it on terminal

```js
┌──(kali㉿kali)-[~/Downloads/skrctf/ThekolonaVirusv2]
└─$ python solving.py 
import random
flag = open("flag.png","r")
kolona = open("flag.kolona","w+")
key = "SARS-CoV-2"
# Prevent Reverse Engineering!
random_num = random.randint(1,6666)

for i,c in enumerate(flag.read()):
        kolona.write(chr((ord(c) + ord(key[i % len(key)]) + random_num) % 256))
```

Finally got the original code used to decrypt the flag. Just gotta reverse engineer this to get the flag.png.

```py
key = "SARS-CoV-2"

def decrypt_kolona(encrypted_data, key, random_num):
    decrypted_data = bytearray()
    key_len = len(key)
    for i, c in enumerate(encrypted_data):
        decrypted_byte = (c - ord(key[i % key_len]) - random_num) % 256
        decrypted_data.append(decrypted_byte)
    return decrypted_data

with open("flag.kolona", "rb") as kolona_file:
    encrypted_data = kolona_file.read()

for random_num in range(1, 6667):
    decrypted_data = decrypt_kolona(encrypted_data, key, random_num)
    if decrypted_data[:8] == b'\x89PNG\r\n\x1a\n':   ## valid PNG file signature (first 8 bytes in hex: 89 50 4E 47 0D 0A 1A 0A) ASCII representation
        with open("decrypted_flag.png", "wb") as output_file:
            output_file.write(decrypted_data)
        print(f"Successfully decrypted with random_num = {random_num}")
        break

```

And just gotta run that ...

And finally got the png

![flag](/assets/img/TheKolonaVirusV2/decrypted_flag.png)




**Flag:** SKR{W3_will_W1N!!}

Završi!!!

Finally finished my first hard level CTF 

![emoji](/assets/img/TheKolonaVirusV2/image-1.png)

