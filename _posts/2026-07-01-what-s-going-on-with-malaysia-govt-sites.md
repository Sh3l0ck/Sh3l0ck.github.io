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
 
The extension in question is JCE (Joomla Content Editor), basically the most popular WYSIWYG editor plugin for Joomla sites, sitting on hundreds of thousands of installs worldwide. Every version from 1.0.0 up to 2.9.99.4 was affected. CVSS score of 10.0, tracked under CWE-284 (Improper Access Control), which is about as bad as it gets on paper.
 
Here's roughly how the attack chain works:
 
1. **No login needed to create a profile.** JCE lets admins set up "editor profiles" with their own permissions, things like which file types can be uploaded and where. Turns out the endpoint that imports/creates these profiles never actually checked whether the request was coming from an authenticated session. All an attacker needs is a CSRF token, and Joomla helpfully drops that token right on the public homepage for anyone to grab.
2. **Mess with the allowed file types.** Once the rogue profile exists, the attacker edits it to allow file types it really shouldn't, like `.php`, instead of the images/media types it's supposed to be limited to.
3. **Drop a web shell.** Upload a PHP web shell into a public facing folder, usually somewhere under `images/` or the plugin's temp directory, using the newly permissive profile.
4. **Free RCE.** Hit the uploaded shell in a browser and you've got remote code execution as the web server user. No creds, no phishing, no social engineering, just an unauthenticated HTTP request chain from start to finish.  
It's a pretty textbook access control failure once you break it down: a feature meant for trusted admins, reachable by anyone, because nobody checked who was calling it. And because the RCE lands as the web server process, attackers weren't just limited to defacing the homepage, advisories flagged follow on risk like backdoor persistence, credential harvesting from the Joomla DB config, and lateral movement into whatever else shared that hosting environment.
 
![We dont do that here meme](/assets/img/WhatsGoingOnWithMalaysiaGovt/fail-list-you-had-one-job-751621.jpg)
<!-- meme idea: something like the "we don't do that here" format, or a "one job" style caption over "check who's calling the function" -->
 
## Timeline, because the gap here is the real story
 
- **June 3, 2026** — Widget Factory (the JCE vendor) quietly ships the fix in version 2.9.99.5. No fanfare, just a changelog entry.
- **June 16, 2026** — CISA adds CVE-2026-48907 to its Known Exploited Vulnerabilities catalog after confirming active exploitation in the wild, and gives US federal agencies until June 19 to patch. Three days. One of the shortest windows CISA's handed out.
- **June 26, 2026** — Closer to home, Malaysia's NC4 (National Cyber Coordination and Command Centre) publishes an advisory tying several compromised government sites to this exact flaw, and pushes admins to update to 2.9.99.6, or 2.9.99.5 at minimum.
- **June 27, 2026** — Screenshots of the MOH homepage defaced start circulating on social media.
Thirteen days between a patch quietly landing and a federal "drop everything" order. Then another week before it showed up as actual defacements on this side of the world. That gap is basically the whole story: the fix existed, plenty of sites just hadn't gotten to it yet.
 
# The Malaysia Angle
 
This is where it got local. NACSA (National Cyber Security Agency) put out an advisory through NC4 flagging that several Malaysian government sites had been compromised through this exact JCE flaw, including the Ministry of Health (MOH), the Malaysia Co-operative Societies Commission (SKM), the Handicraft Development Corporation (Kraftangan Malaysia), and the Women's Development Department (JPW). Four agencies with basically nothing in common except that they all happened to run the same unpatched CMS extension, which honestly says a lot about how this kind of attack actually works. It's not a targeted campaign against any one of them, it's opportunistic scanning that finds whoever forgot to update.
 
The MOH site got the worst of it. Its homepage was defaced with a message reading "HACKED BY MUSHR00W," styled with the usual Anonymous-flavoured "we are legion" flair, and screenshots were doing the rounds on social media within hours. MOH confirmed the incident on Facebook, told the public to steer clear of the site and avoid clicking anything on it in the meantime, and eventually took the whole portal offline to work on it, which given the circumstances feels like the right call.
 
![MOH hacked site](/assets/img/WhatsGoingOnWithMalaysiaGovt/moh-hacked.jpeg)
 
Worth noting, defacement banners aren't the same thing as confirmed attribution. A group slapping its name on a hacked homepage tells you what they wanted people to see, not necessarily who actually pulled it off or whether "Mushr00w" is even the full extent of who got in. As of writing, no attribution here has been officially confirmed, just the group's own claim.
 
![Stressed out gif](/assets/img/WhatsGoingOnWithMalaysiaGovt/stressed-out.gif)
 
The other three sites (SKM, Kraftangan Malaysia and JPW) didn't get the same media attention as MOH, but were named in the same NC4 advisory, and NACSA flagged that patching alone isn't enough for any of the affected entities, since a webshell or rogue editor profile dropped before the patch would just sit there waiting even after JCE gets updated. Compromise assessment, not just a version bump, was the actual advice.
 
# Takeaway
 
Big scary CVEs get headlines, but the boring stuff, patch cadence, upload restrictions, access control on "admin only" features, is what actually keeps you off the news. This one's a good reminder that a maximum severity bug doesn't need to be exotic to do maximum damage, it just needs someone somewhere to skip an update, and a two week gap between "patch available" and "actively exploited" is apparently all it takes these days.
 
Stay patched people.
 
Aloha!!