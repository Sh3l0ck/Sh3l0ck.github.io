---
layout: post
title: Secret Coffee Nut Stash
date: '2024-05-14 00:00:00 +0000'
categories: [WriteUps]
tags: [squ1rrelCTF, Reverse Engineering]  
---

# Secret Coffee Nut Stash

You'll never be able to break into my secret Java coffee nut stash!

**File:** ([CoffeNutStash.class](assets\img\SecretCoffeeNutSlash\CoffeNutStash.class))

**Type:** Reverse Engineering

# Solutions
First things first after downloading the file given to me in this challenge. I noticed it was a java compiled file so I immidiately threw it into ghidra to decompile and understand the code. 

![ghidra_screenshot](assets\img\SecretCoffeeNutSlash\ghidra_screenshot.png)

Got a bunch of nonesense I couldn't quite understand.....

So I decided to use a proper java decompiler (jadx-gui) to decompile and try to understand this file

![jadx-gui_screenshot](assets\img\SecretCoffeeNutSlash\jadx-gui_screenshot.png)

Finally some code I can understand.

To solve this I just wrote a short python sctipt to reverse and print the flag using the expected array


```python
expected = [578, 568, 588, 248, 573, 573, 508, 543, 618, 258, 553, 533, 243, 608, 478, 608, 243, 588, 573, 478, 533, 263, 593, 263, 478, 498, 243, 513, 513, 258, 258, 478, 273, 258, 288, 253, 278, 263, 628]

charArray = []

for i in range(len(expected)):
    charArray.append((expected[i] - 3) // 5)


flag = ''.join(chr(char) for char in charArray)

print(flag)
```

Output is squ1rrel{3nj0y_y0ur_j4v4_c0ff33_639274}

And there we have it 

**Flag:** squ1rrel{3nj0y_y0ur_j4v4_c0ff33_639274}

Finir !!!
