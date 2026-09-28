---
layout: post
title: 'Holmes CTF 2026: Cracking the Reichenbach Directive'
date: 2026-09-23 20:42 +0800
categories: [WriteUps]
tags: [reverse engineering, vulnerability analysis, HTB ctf, DFIR]
---

# Intro

Tried the Holmes CTF 2026 - The Reichenbach Directive over the weekend window, HTB's whole Sherlock format wrapped around a proper Holmes-flavoured story this time an intresting spin on the usual ctfs one would encounter.Did 4 Sherlocks in total, this post covers 3 of them. Save the 4th for a follow up once I've written it up properly.

The challenegs (sherlocks) were a mixed bag difficulty and category wise, one was straight reverse engineering against an obfuscated LuaJIT payload, one was pure DFIR against a Windows triage folder, and one was a full disk image investigation that turned into a battle against someone who very deliberately tried to wipe their own tracks. That Bottle-Out DFIR ended up being my favourite of the four, so it gets the most detail at the end. First time I got to actually rdp into a live windows environement and investigate.

![Main pic](/assets/img/HolmesCTF2026/main-screen.png)

---

## Sherlock 01 - Silent Dividend (Medium, Reverse Engineering)

**Result:** 10/10 flags · 800 points
**Target:** `TrustSettle 1.0.0.exe` - an Electron desktop app hiding an obfuscated LuaJIT payload and a web3/smart-contract layer

### Challenge

Scenario shows up as a PDF (the story), a `DANGER.txt` malware warning, and a password protected zip containing a `README.md` and the exe itself. Ground rule from the jump: treat it as live malware, everything gets analyzed in an isolated VM, nothing touches the host, no real wallet goes near whatever contract this thing references. The goal of this ctf is to solve each question gives to obtain a flag.


![Silent Dividend Main pic](/assets/img/HolmesCTF2026/silent-dividend-main.png){: height="200" }


### Solution

First things first before I'd even opened anything. Tried extracting the zip with:

```powershell
& "C:\Program Files\7-Zip\7z.exe" x "C:\path\to\danger.zip" -p"E9$LQ2@Mr7A!" -o"C:\path\to\out"
```

Wrong password, twice. Turns out PowerShell interpolates `$` inside double quoted strings, so `$LQ2` got parsed as an empty variable and silently mangled my password before it even reached 7-Zip. Swapped to single quotes (fully literal, no interpolation) and it worked first try.

```powershell
& "C:\Program Files\7-Zip\7z.exe" x "C:\path\to\danger.zip" -p'E9$LQ2@Mr7A!' -o"C:\path\to\out"
```

The exe itself is an NSIS based Electron installer, extracted it without ever running it:

```powershell
& "C:\Program Files\7-Zip\7z.exe" x ".\TrustSettle 1.0.0.exe" -o".\extracted_exe"
Get-ChildItem -Recurse .\extracted_exe | Where-Object { $_.Name -like "*asar*" -or $_.FullName -like "*extraResources*" }
```

That folder layout answers **Flag 1** straight away, no execution needed, `resources\extraResources\` is where the bundled files land. Sitting inside it: `api.txt`, a 66 KB obfuscated LuaJIT script, plus `luajit.exe`, the runtime to run it with.

#### First pass: sandbox it

Before going static-only on the Lua file I ran the sample through Triage to get a read on process/network behaviour first.

Confirmed a full spawn chain: `TrustSettle.exe → cmd.exe → powershell.exe -exec bypass -w hidden → luajit.exe C:\Users\Public\api.txt`, later a `cmd.exe` popping `settlement.html` with an `AUTH=NAPOLEON` echo, a Sepolia RPC call, and `settlement.html` pulling `ethers.umd.min.js` off a jsDelivr CDN.

What it didn't give me was anything on `luajit.exe` itself, no outbound HTTP from that process in the capture at all. My best guess is the script's directory watcher only fires its HTTP call on an actual file change event, which never happened during the sandbox run. That's what pushed me off "just read it out of the sandbox report" and onto "make the script tell me itself."

#### Flags 2 & 3: instrumenting the obfuscation

`api.txt` isn't readable Lua, it's Luraph/Prometheus-style VM obfuscated output, a big table of encoded strings up front followed by a custom bytecode interpreter that decodes and dispatches at runtime. A plain `Select-String` for `WinHttp|Internet|ReadDirectoryChanges` came back completely empty because none of that exists as readable text in the file.

Here's the insight that cracked it though: LuaJIT can only talk to Win32 through its FFI. `ffi.cdef(...)` to declare the C signatures, `ffi.load(...)` to load a DLL, then calls through the resulting table. Doesn't matter how obfuscated the surrounding logic is, the moment it wants to actually call a Windows API it has to hand LuaJIT a plain text C declaration and DLL name, the FFI itself just doesn't support obfuscated input. So instead of reversing the VM bytecode, plan was: swap out the real `ffi` module for a fake one that logs everything passed to it, then run the still-obfuscated script against that.

Built a harness (`hook.lua`) that:
- Registers a fake `ffi` table in `package.loaded`/`package.preload`, so `require("ffi")` inside `api.txt` gets my fake
- Logs every `ffi.cdef(...)` string verbatim, every `ffi.load(...)` DLL name, every function looked up or called through the resulting library object
- Returns an inert dummy object from every faked call so the script keeps running instead of crashing on `nil`
- Blocks `os.execute`, `io.popen`, `os.remove`, `os.rename`, real `io.open`, just logs any attempt
- Wraps `loadstring`/`load` to log anything the script builds and runs at runtime
- Installs a `debug.sethook` instruction count trap, since the watcher loop would otherwise run forever
- Loads and runs `api.txt` via `loadfile` + `pcall`, dumps everything to `hook_log.txt`

```powershell
cd "...\danger\app64\extraResources"
.\luajit.exe hook.lua api.txt
Get-Content .\hook_log.txt
```


Still run inside the sandboxed VM since the harness never actually lets a real Win32 call fire, but the sample itself was still executing.

Out came this:

```
LOAD: winhttp
CDEF: typedef void *HANDLE; typedef int BOOL; typedef unsigned long DWORD;
typedef wchar_t WCHAR; typedef void* HINTERNET; ...
HINTERNET WinHttpOpen(...);
HINTERNET WinHttpConnect(...);
HINTERNET WinHttpOpenRequest(...);
BOOL WinHttpSendRequest(...);
BOOL WinHttpReceiveResponse(...);
BOOL WinHttpQueryDataAvailable(...);
BOOL WinHttpReadData(...);
BOOL WinHttpCloseHandle(...);
DWORD GetLastError();
HANDLE CreateFileW(...);
BOOL ReadDirectoryChangesW(...);
BOOL CloseHandle(HANDLE hObject);
typedef struct {
  DWORD NextEntryOffset;
  DWORD Action;
  DWORD FileNameLength;
  WCHAR FileName[1];
} FILE_NOTIFY_INFORMATION;
LOAD: kernel32
LOOKUP: C.CreateFileW
CALL: C.CreateFileW dummy 2147483648 7 nil 3 33554432 nil
LOOKUP: C.GetLastError
FINISHED: false ... hook: os.exit called
```


Run only got as far as `CreateFileW` before hitting my fake return and bailing via `os.exit`, but didn't matter, the entire API surface got declared up front in one shot before any of it was even called.

**Flag 2:** was solved.

**Flag 3:** was solved.

#### Flags 4-10, the honest version

Ngl, I burned through these before I started keeping proper notes on my process, so I can't walk you through the exact steps the way I did for 2 and 3. What I do remember: `resolveState()` was the contract call the app makes to fetch the decryption key, decoding the encrypted payload against that contract logic got me `AUTH=NAPOLEON SETTLEMENT_REFERENCE=SR-4821`, `%TEMP%` is the env var backing the HTML drop location, `settlement.html` calls `approve()` on the token contract requesting the maximum possible allowance (`115792089237316195423570985008687907853269984665640564039457584007913129639935`, that's `2^256 - 1`, i.e. unlimited approval, which on its own is a nice little "yeah this is definitely malicious" detail), the wallet connection goes through ethers v6's `BrowserProvider`, and the final hidden flag off the HTML's contract reference resolved to a coordinate pair, `51.5049,0.0348`.

Lesson learned here: for a 10 flag chained challenge, jot a one line "flag X: answer, one line method" as you go. Would've saved me writing this paragraph.

Fun one overall, the FFI-hooking trick is going straight into my toolbox for the next obfuscated Lua sample I run into.

---

## Sherlock 02 - Bottle Out (Easy, DFIR)

**Result:** 9/10 flags · 1000 points
**Target:** `DESKTOP-QMTIG5I.E01`, a 13.9 GB forensic image, analyzed from a pre-built Windows DFIR VM via RDP

This one was my favourite of the four. Started off looking like a straightforward "run some EZ-Tools" easy box and turned into a genuine cat and mouse against someone who tried very hard to wipe their tracks.

### Challenge

Connect over OpenVPN, RDP into `10.129.4.171` (`Administrator:Holmes2026!`), find a `.E01` sitting on the analyst's own Desktop, answer 10 questions tied to a Sherlock Holmes kidnapping/fraud narrative spread across 3 accompanying story PDFs.


![Bottled Out Main pic](/assets/img/HolmesCTF2026/bottled-out-main.png){: height="200" }


### Solution

#### Setup, and the first self-inflicted wound

Ran `nmap -Pn -sS -p 22,80,445,3389,5985` against the target, only SSH/RDP/WinRM open. Spent an embarrassing number of minutes trying blind SSH logins and CrackMapExec probes against SMB/WinRM before realizing the creds were sitting in plain text in the scenario's own description panel, just below the fold I hadn't scrolled to. Lesson relearned the hard way: read the whole scenario description before you start throwing tools at anything.

![RDP desktop with E01 file](/assets/img/HolmesCTF2026/Bottled-out-first.png)

Once in, Desktop had the `.E01` and a `Tools.lnk` pointing at a full DFIR/reversing kit under `C:\Tools\`, Debuggers, EZ-Tools, Forensics, MemoryAnalysis, Reversing, the works. Pretty clear signal the intended path was mount the image and parse specific artifact types with EZ-Tools rather than any live exploitation.

Mounted two different ways depending on what I needed: FTK Imager's "Add Evidence Item" for normal browsing as `D:\`, and later FTK's raw evidence tree with the `[orphan]` folder once it became clear basically everything relevant had been deliberately deleted (more on that below). One recurring annoyance worth flagging: FTK's "Load Hive"/"Open" dialogs default to filtering for `*.LOG` files, which hides the actual extensionless hive files (`SOFTWARE`, `SYSTEM`, `SAM`, `NTUSER.DAT`). Fix is either flipping the filter to "All files" or just typing the full path straight into the filename box.


#### Flags 1-3: the VPN connection (and my biggest mistake of the whole CTF)

Flags asked for the VPN server's remote address:port, the CA that issued the client cert, and the IP assigned "to the user" by the VPN server. Because I'd literally just connected to the box over my own OpenVPN session, my first instinct was to answer all three using my own connection, HTB's edge server IP, my own client cert's issuing CA, my own `tun0` IP.

All three rejected. Spent longer than I'd like to admit re-verifying my `openssl x509 -noout -issuer` command was even right (it was) before it clicked: "the user" means `spur`, the victim on the machine I'm investigating, not me. Classic own-goal when the first 3 flags happen to be VPN-shaped and you've just used a VPN to get there.

Went looking for `spur`'s own VPN usage instead. Every obvious location came up empty, `OpenVPN\config\` folders with nothing but stock placeholder READMEs, `AppData\Roaming\OpenVPN` not existing at all. That pattern, install evidence present but no live config, was my first real signal something had been deliberately deleted.

Recovery method from here on out: parsed the USN Change Journal with MFTECmd.

```powershell
MFTECmd.exe -f 'D:\$MFT' -m 'D:\$Extend\$UsnJrnl:$J' --csv <output> --csvf usnj.csv
```

Filtered the CSV in TimelineExplorer for `.ovpn`, found two entries for `spur.ovpn` (one staged, one fully written, both deleted at the same timestamp). Tried hunting it down in FTK's `[orphan]` tree manually, genuinely painful since orphan entries aren't labeled by original parent folder. The actual break came from noticing a `spur.log` sitting alongside the Gajim-adjacent orphaned content, not the config itself, but the OpenVPN GUI's connection log. Way more useful than the config would've been, since it's the actual negotiated session in plaintext:

```
2026-09-01 05:21:10 TCP/UDP: Preserving recently used remote address: [AF_INET]18.156.81.166:7577
...
2026-09-01 05:21:10 VERIFY OK: depth=1, CN=NPLN-CA
2026-09-01 05:21:10 VERIFY OK: depth=0, CN=NPLN-VPN-7577
...
2026-09-01 05:21:10 PUSH: Received control message: 'PUSH_REPLY,...,ifconfig 10.129.175.2 255.255.255.0,...'
...
2026-09-01 05:21:15 MANAGEMENT:>STATE:1788265275,CONNECTED,SUCCESS,10.129.175.2,18.156.81.166,7577,,
```

One file, all three flags, no further parsing required.

**Flag 1:** solved
**Flag 2:** solved
**Flag 3:** solved

Retrospective lesson here that's stuck with me: a connection *log* is often a better target than the connection *config*, the log captures what actually happened, the config only states intent.

#### Flags 4-6: the remote management agent

Flag wording pointed at software, not a person. Registry Explorer's built-in bookmark panel had entries literally named `Communication_NtUser_TeamViewer`, and I almost ran with "must be TeamViewer" before catching myself, those are generic templates that ship with the tool for common RMM software, not case-specific findings. Actual installed software, found by just browsing `D:\Program Files\` directly, was `TacticalAgent`, Tactical RMM, a real open source remote monitoring tool.

Double-clicking `tacticalrmm.exe` cold popped "Tactical RMM v2.11.0", which got rejected, along with a couple of reworded variants. Checked the exe's own Properties → Details tab instead:

![tacticalrmm.exe file properties](/assets/img/HolmesCTF2026/TacticalGent-screenshot.png)

Description field: `Tactical RMM Agent`. Combined with the version, exact match for the flag's own format hint (`Agent Name v.X.Y.Z`).

**Flag 4:** solved

Domain and token came from the registry. Loaded `D:\Windows\System32\config\SOFTWARE` into Registry Explorer (typing the path directly to dodge the `*.LOG` filter again), accepted the dirty hive replay prompt, searched for `Tactical`, landed on the `TacticalRMM` key with plaintext values sitting right there:

**Flag 5:** solved
**Flag 6:** solved

#### Discovering Operation Vanish

By this point the pattern was undeniable, every "obvious" evidence location was empty. No `.ovpn`, no Gajim folder where it should be, nothing. This is what flipped my default approach from "browse live filesystem, get surprised by empty folders" to "assume it's deleted, go straight to USN Journal + orphan recovery."

Parsed the Security event log for process creation events:

```powershell
EvtxECmd.exe -f 'D:\Windows\System32\winevt\Logs\Security.evtx' --csv <out> --csvf security.csv
```

1,362 Event ID 4688 records, way too many to scan blind. Used the USN Journal's precise deletion timestamps for the Gajim folder (clustered around `12:37:26`-`12:37:52`) to narrow the 4688 window down to about 20 candidates, mostly noise (VMware Tools, TacticalRMM's own heartbeat), except this one:

```
12:37:39 — Parent: tacticalrmm.exe → New process: cmd.exe
CommandLine: cmd.exe /C powershell -NonI -NoP -W 1 -Enc <long base64 string>
```

Decoded the base64 (PowerShell `-EncodedCommand` is UTF-16LE under the hood, not raw ASCII, worth remembering) to get:

```powershell
# Operation Vanish
$folders = @(
    "C:\Users\spur\Gajim",
    "C:\Users\spur\OpenVPN",
    "C:\VPN"
)
foreach ($folder in $folders) {
    Remove-Item -LiteralPath $folder -Recurse -Force
}
```

Genuinely satisfying find, it names itself, and its three targets account for every missing-evidence mystery up to that point. The flag's masked length hint matched the first line of the loop body exactly.

**Flag 7:** solved

#### Flags 8-9: recovering the deleted Gajim profile

Prefetch confirmed `GAJIM.EXE` ran 11 times but no folder existed anywhere live. Guessed the usual `AppData` locations, all wrong. Prefetch's own directory reference list gave it away though, runtime files lived straight off `C:\Users\spur\Gajim\`, not under any AppData subfolder like a normal portable app.

Re-ran the USN Journal search, this time just for the exact string `Gajim`, surfaced the top-level folder's entry number. Filtered `Parent Entry Number` to that and got the full child list: `bin`, `etc`, `lib`, `share`, and critically `UserData`. One more filter pass on `UserData`'s entry number gave me the full profile contents, including `omemo_spurio9@murknet.htb.db`, first confirmation of the actual account JID.

Located `Settings.sqlite` (20,480 bytes) in FTK's orphan tree by scrolling alphabetically to "U", exported it.

![FTK Imager exporting Settings.sqlite](/assets/img/HolmesCTF2026/ftk-imager.png)

First read was straight off the hex dump in FTK's preview pane, readable enough to transcribe a JSON blob out of. Submitted off that read, flag 8 landed correct, flag 9 didn't. Rather than re-guess, queried it properly instead:

```powershell
python3 -c "import sqlite3; conn = sqlite3.connect(r'C:\...\Settings.sqlite'); cur = conn.cursor(); ..."
```

**Flag 8:** solved
**Flag 9:** solved

Big transferable lesson from this one: once you know a file's a real structured format and it opens at all, query it through its native library, don't transcribe off a hex/strings view. Hex dumps are fine for confirming data exists, not for reading it precisely.

#### Flag 10: the jailer's full name (didn't get it)

This one beat me. Ran out of session time chasing it. The story PDFs point hard at XMPP/Gajim conversation data specifically for the answer, "The Voices Behind the Names" as a chapter title isn't subtle. Problem is `Logs.db`, Gajim's actual chat history, recovered from the orphan tree but comes back `database disk image is malformed`. Raw string scans show the schema is intact, `CREATE TABLE` statements and all, but almost no row data survived, whatever wrote to those disk clusters afterward overwrote the actual message rows while the schema pages happened to survive.

Tried `openpgp.db` (same story), the `Bob` folder (genuinely empty, 0 bytes even in the original listing), `Cache.db` (didn't survive a second orphan browse attempt), Windows Contacts (empty), Jump Lists (parsed clean, nothing new), Chrome history (0 rows, unused profile), and the SAM registry's Full Name field on `spur`'s account (never set).

The lead I didn't get to try before time ran out: `Logs.db-wal` and `Logs.db-shm`, SQLite's write-ahead-log sidecars, both visible in the same USN journal listing as `Logs.db` itself. WAL-mode databases write new rows to the WAL file first and only periodically checkpoint into the main file. Entirely plausible the messages that got overwritten in the main file's pages are still sitting intact in the WAL. If I go back to this one, that's step one.

**Flag 10:** unresolved


Still my favourite of the four, purely because of how much the "assume it's deleted" pivot changed the whole shape of the investigation halfway through. 

---

## Sherlock 04 - The Paper Ghost (DFIR)

**Result:** 9/9 flags
**Target:** `CO-LT-0469`, Clara Voss's laptop, triage collection only (no live disk image this time)

### Challenge

Story goes: a contractor badge walked the corridor near Clara Voss's office, she used a device presented as an "update", what happened and who was responsible stayed unproven. Given a triage folder off her laptop and asked to prove it.

![Bottled Out Main pic](/assets/img/HolmesCTF2026/paper-ghost-main.png){: height="200" }


### Solution

Folder had registry hives, transaction logs, Jump Lists, SRUM, a Windows Search database. Notably missing: event logs, Prefetch, Amcache. So from the jump I knew every answer had to come from whatever survived in that specific artifact set.

Before touching anything, mapped each question to where Windows would've logged the answer. USB connections live in the SYSTEM hive, execution shows up in UserAssist, mic/webcam sessions get logged in the consent store, network volume lives in SRUM, whatever was on screen might be in the search index. Nine questions, five hiding places.

Tooling setup was its own small saga, first command failed because `LECmd.exe` wasn't where expected, the downloader wanted a .NET version that wasn't installed, tools landed in a `net9` folder that needed .NET 8 not 9. Few rounds of that before finally getting "Processed 8 out of 8 files."

#### The lure, and a detour

First lead was Clara's Recent files, four shortcuts: `DIOGENES_26`, `Driver Update Package`, `EXT-0419`, `IT_SUPPORT`. Parsed with LECmd expecting a path to something malicious.

Every one pointed at local disk, a folder on her Desktop, these were the lure documents, a fake "Driver Update Package" PDF with install instructions plus a contractor file and IT note. Showed what she'd opened, not what had run. Felt like a dead end but taught me the payload was elsewhere and I needed execution artifacts, not file-opening ones. Also picked up a detail that mattered a lot later: `EXT-0419.pdf` had been open on her screen.

#### Flag 8, the first to fall: SRUM

Parsed SRUM, sorted network usage by bytes sent. Mostly background noise, Windows Update, Delivery Optimization, Edge at 5 MB. Then one row:

```
\device\harddiskvolume5\co-lt-0469 update package\update.exe - 172,064,531 bytes sent
```

Thirty times the browser, from a program sitting in a folder called "CO-LT-0469 Update Package" on a completely different volume than the OS. That's the spyware talking. Question wanted decimal megabytes, divided by 1,000,000 not 1,048,576.

**Flag 8:** solved

Now I had a process name and a folder to pivot off of.

#### Flags 2, 3 & 4: the registry

Ran the whole registry through RECmd's Kroll batch, filtered the resulting CSV for the process name, computer name, and USB storage. Three things fell out.

The USB drive, a Lexar flash drive in USBSTOR with serial `RS200000000627E4&0` (the `&0` is a Windows-added suffix, the device's own serial is everything before it).

**Flag 2:** solved

The path, minus a drive letter, SRUM gave the folder but not the letter, AppCompatCache didn't have it either. UserAssist did though, an entry named `R:\PB-YG-0469 hcqngr cnpxntr\hcqngr.rkr`. That's ROT13. Shifted, it reads `E:\CO-LT-0469 update package\update.exe`. MountedDevices confirmed `E:` had been a mounted volume.


**Flag 3:** solved

Same UserAssist entry carried a last-executed timestamp.

**Flag 4:** solved

Hesitated over timezone here, registry said Pacific but timestamps are stored UTC and the tool prints UTC. Submitted raw, accepted. Trust the storage format, not the system clock display.

#### Flag 1: first connection, not last write

USBSTOR key's last-write time was `15:35:50`, tempting to just submit that, but a key's last-write isn't the same thing as first connection. Loaded the SYSTEM hive in Registry Explorer properly (replaying the transaction log), navigated to the device's property GUID, subkey `0064` holds the actual first-install time.

Read `2026-08-19 15:35:50`, same instant as the last-write in this case, but now confirmed rather than assumed.

**Flag 1:** `2026-08-19 15:35:50`

Drive went in at `15:35:50`. 35 seconds later, `update.exe` ran.

#### Flag 5: the name on the drive

Question wanted the asset name DIOGENES tagged the USB with, surfacing as its device name on connection. The obvious `FriendlyName` ("Lexar USB Flash Drive USB Device") was just the generic driver string. Chased a few hex-encoded property values that decoded to nothing more than the drive's VID/PID link, dead end.

Real label was in the other device-name entries Windows generates on volume mount, an internal asset tag.

**Flag 5:** solved

#### Flags 6 & 7: someone was listening

Mic/webcam usage logs live in the NTUSER hive, under `CapabilityAccessManager\ConsentStore`. For non-packaged apps like `update.exe`, entries sit under `NonPackaged` with backslashes swapped for `#`.

Found `E:#CO-LT-0469 update package#update.exe` under microphone, start time:

**Flag 6:** solved

Two minutes 43 after execution, mic goes live.

Webcam is where I actually stumbled. First pass I subtracted the mic's start time from the webcam's stop time and got 387 seconds, wrong. Each device has its own independent Start/Stop pair:

```
Start: 134316277486814313 (15:42:28)
Stop:  134316278756619812 (15:44:35)
Difference: 1,269,805,499 ticks / 10,000,000 = 126.98 seconds
```

**Flag 7:** solved

Camera came on 4 minutes after the mic, watched the office for just over 2 minutes.

#### Flag 9, the hardest one: what was on screen

No timestamp or serial to look up for this one, had to work out what could actually be seen. Nothing in the registry or shortcuts held a password, but the earlier LNK detour left a breadcrumb, `EXT-0419.pdf` on the Desktop, and the Windows Search index had crawled it, extracted text and all.

Getting the text out took the most effort of the whole Sherlock:
1. Tried SIDR, wasn't installed
2. Tried a raw regex against the database directly, PowerShell froze solid, one regex chewing a huge string in one call
3. Wrote a compiled string dumper instead, ran fast but only surfaced file paths, the actual index text is compressed
4. Downloaded SIDR, got source instead of a binary the first time, second try got the compiled `sidr.exe`, remembered PowerShell needs `.\` for local exes, ran it


SIDR's File Report, row 89, had the full extracted text of `EXT-0419.pdf`:

```
Tom Ainsworth, Software Developer, DIOGENES Ticketing Support (External Contractor)
Username: tainsworth
Password: D10g3n3s_T1ck3ts#2026
```

Activity history sealed it, Edge had the PDF open `15:38:27` to `15:45:05`, a window overlapping both the mic (from `15:38`) and the webcam (`15:42`-`15:44`). While Clara was reading the contractor's file, she was being watched and listened to at the same time.

**Flag 9:** solved


---

## Conclusion

That's 3 of the 4 done. Bottle Out's flag 10 still annoys me, but overall it was a challenging and intresting ctf to participate in. Fourth Sherlock write-up coming separately once it's ready.

Honestly. Damn did I do a lot better then I thought I would.

![I am smart](/assets/img/HolmesCTF2026/smart.gif)

Auf Wiedersehen!!!

