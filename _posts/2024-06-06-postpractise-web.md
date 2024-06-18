---
layout: post
title: PostPractise - Web
date: '2024-05-14 00:00:00 +0000'
categories: [WriteUps]
tags: [ctflLearn, web]  
---

# Intro

While browsing through the CTFLearn medium level challenges this challenge ciught my eye. So I thought why not I try my hand at this

# Problem

At first sight I was very cofused on what to do to solve this problem till i inspected the webpage to find the username 
and password commented out. It seemed from here on it was an uphill battle

![Webpage](/assets/img/PostPractiseWeb/Screenshot-2024-02-28-144421.png)


# Solution

After messing around with python a bit I came accross 'curl' which seem to be the way to solve this challenge

```terminal
$ curl http://165.227.106.113/post.php -d "username=admin&password=71urlkufpsdnlkadsf"
```


Just using the admin and password identified before when I inspected the page and I got the flag

**Flag:** CTFLearn{p0st_d4t4_4ll_d4y}