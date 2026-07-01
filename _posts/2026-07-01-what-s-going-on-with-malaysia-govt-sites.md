---
layout: post
title: What's going on with Malaysia govt sites?
date: 2026-07-01 16:47 +0800
categories: [WriteUps]
tags: [news, vulnerability analysis]
---

# Intro

Not a CTF this time, but something that hit way closer to home. Late June 2026, a bunch of Malaysian government websites started going down and getting defaced, including MOH's own site. Being based here, this one caught my attention way more than usual, so I figured I'd break it down writeup style like I do with challenges.

Spoiler: this wasn't some crazy nation state zero day. It was a known, patched vulnerability in a Joomla plugin that a lot of people just didn't get around to updating. Classic.

![Facepalm Meme](/assets/img/WhatsGoingOnWithMalaysiaGovt/Facepalm_Meme_Video_Download.gif)

<!--[insert reaction gif here](/assets/img/WhatsGoingOnWithMalaysiaGovt/Facepalm_Meme_Video_Download.mp4) -->
<!-- meme idea: facepalm energy, or "this is why we can't have nice things" vibe -->

# The Bug - CVE-2026-48907

The extension in question is JCE (Joomla Content Editor), basically the most popular WYSIWYG editor plugin for Joomla sites. Every version before 2.9.99.4 was affected. CVSS score of 10.0, which is about as bad as it gets.

Here's roughly how the attack chain works:

1. **No login needed to create a profile.** JCE lets admins set up "editor profiles" with their own permissions. Turns out the endpoint that imports these profiles never actually checked who was asking. All an attacker needs is a CSRF token, and Joomla helpfully drops that token right on the public homepage for anyone to grab.
2. **Mess with the allowed file types.** Once the rogue profile exists, the attacker edits it to allow file types it really shouldn't, like `.php`.
3. **Drop a web shell.** Upload a PHP web shell into a public facing folder, usually somewhere under `images/` or the plugin's temp directory.
4. **Free RCE.** Hit the uploaded shell in a browser and you've got remote code execution as the web server user. No creds, no phishing, no social engineering.

It's a pretty textbook access control failure once you break it down: a feature meant for trusted admins, reachable by anyone, because nobody checked who was calling it.

![We dont do that here meme](/assets/img/WhatsGoingOnWithMalaysiaGovt/fail-list-you-had-one-job-751621.jpg)
<!-- meme idea: something like the "we don't do that here" format, or a "one job" style caption over "check who's calling the function" -->

The vendor patched this in JCE 2.9.99.5, and CISA added it to their Known Exploited Vulnerabilities list not long after, giving federal agencies a painfully short window to patch.

# The Malaysia Angle

This is where it got local. Nacsa put out an advisory through NC4 flagging that several Malaysian government sites had been compromised through this exact JCE flaw, including the Ministry of Health, the Malaysia Co-operative Societies Commission, the Handicraft Development Corporation, and the Women's Development Department.

The MOH site got the worst of it, defaced by a group going by "Mushr00w," with screenshots doing the rounds on social media pretty quickly after. MOH put out a statement saying they were investigating an "access disruption" believed to be linked to a cybersecurity incident, which is the polite way of saying "yeah we got popped."

![MOH hacked site](/assets/img/WhatsGoingOnWithMalaysiaGovt/moh-hacked.jpeg)


![Stressed out gif](/assets/img/WhatsGoingOnWithMalaysiaGovt/stressed-out.gif)


# Takeaway

Big scary CVEs get headlines, but the boring stuff, patch cadence, upload restrictions, access control on "admin only" features, is what actually keeps you off the news. This one's a good reminder that a maximum severity bug doesn't need to be exotic to do maximum damage, it just needs someone somewhere to skip an update.

Stay patched people.

Aloha!!
