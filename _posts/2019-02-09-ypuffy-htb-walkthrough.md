---
layout: post
title: "Ypuffy: Hack The Box Walkthrough"
date: 2019-02-09 15:03:23 +0000
last_modified_at: 2019-02-10 04:24:15 +0000
category: Walkthrough
tags: ["Hack The Box", Ypuffy, retired]
comments: true
image:
  feature: ypuffy-htb-walkthrough.jpg
  credit: rmferreira / Pixabay
  creditlink: https://pixabay.com/en/fish-puffer-puffer-fish-underwater-1118874/
---

This post documents the complete walkthrough of Ypuffy, a retired vulnerable [VM][1] created by [AuxSarge][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Ypuffy is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.107 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-20 13:43:48 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.107                                    
Discovered open port 80/tcp on 10.10.10.107                                    
Discovered open port 445/tcp on 10.10.10.107                                   
Discovered open port 389/tcp on 10.10.10.107                                   
Discovered open port 139/tcp on 10.10.10.107
```

Interesting. `masscan` finds five open ports. I'll do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80,445,389,139 -A --reason -oN nmap.txt 10.10.10.107
...
PORT    STATE SERVICE     REASON         VERSION          
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 2e:19:e6:af:1b:a7:b0:e8:07:2a:2b:11:5d:7b:c6:04 (RSA)
|   256 dd:0f:6a:2a:53:ee:19:50:d9:e5:e7:81:04:8d:91:b6 (ECDSA)
|_  256 21:9e:db:bd:e1:78:4d:72:b0:ea:b4:97:fb:7f:af:91 (ED25519)
80/tcp  open  http        syn-ack ttl 63 OpenBSD httpd
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: YPUFFY)
389/tcp open  ldap        syn-ack ttl 63 (Anonymous bind OK)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6 (workgroup: YPUFFY)

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m13s, median: 0s
| smb-os-discovery:
|   OS: Windows 6.1 (Samba 4.7.6)
|   Computer name: ypuffy
|   NetBIOS computer name: YPUFFY\x00
|   Domain name: hackthebox.htb
|   FQDN: ypuffy.hackthebox.htb
|_  System time: 2019-01-20T08:49:37-05:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2019-01-20 13:49:36
|_  start_date: N/A
```

We are probably looking at a OpenBSD box. In any case, I usually go with the `http` service first but this time round, there isn't much going on there. Let's turn our attention to LDAP or `389/tcp`.

### Lightweight Directory Access Protocol

From the nmap scan, we know that the domain is `hackthebox.htb` and in LDAP query language, that's represented as `dc=hackthebox,dc=htb`. We can use `ldapsearch` to search for the objects and attributes from the domain like so.

```
# ldapsearch -h 10.10.10.107 -x -b "dc=hackthebox,dc=htb"

# extended LDIF
#
# LDAPv3
# base <dc=hackthebox,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# hackthebox.htb
dn: dc=hackthebox,dc=htb
dc: hackthebox
objectClass: top
objectClass: domain

# passwd, hackthebox.htb
dn: ou=passwd,dc=hackthebox,dc=htb
ou: passwd
objectClass: top
objectClass: organizationalUnit

# bob8791, passwd, hackthebox.htb
dn: uid=bob8791,ou=passwd,dc=hackthebox,dc=htb
uid: bob8791
cn: Bob
objectClass: account
objectClass: posixAccount
objectClass: top
userPassword:: e0JTREFVVEh9Ym9iODc5MQ==
uidNumber: 5001
gidNumber: 5001
gecos: Bob
homeDirectory: /home/bob8791
loginShell: /bin/ksh

# alice1978, passwd, hackthebox.htb
dn: uid=alice1978,ou=passwd,dc=hackthebox,dc=htb
uid: alice1978
cn: Alice
objectClass: account
objectClass: posixAccount
objectClass: top
objectClass: sambaSamAccount
userPassword:: e0JTREFVVEh9YWxpY2UxOTc4
uidNumber: 5000
gidNumber: 5000
gecos: Alice
homeDirectory: /home/alice1978
loginShell: /bin/ksh
sambaSID: S-1-5-21-3933741069-3307154301-3557023464-1001
displayName: Alice
sambaAcctFlags: [U          ]
sambaPasswordHistory: 00000000000000000000000000000000000000000000000000000000
sambaNTPassword: 0B186E661BBDBDCF6047784DE8B9FD8B
sambaPwdLastSet: 1532916644

# group, hackthebox.htb
dn: ou=group,dc=hackthebox,dc=htb
ou: group
objectClass: top
objectClass: organizationalUnit

# bob8791, group, hackthebox.htb
dn: cn=bob8791,ou=group,dc=hackthebox,dc=htb
objectClass: posixGroup
objectClass: top
cn: bob8791
userPassword:: e2NyeXB0fSo=
gidNumber: 5001

# alice1978, group, hackthebox.htb
dn: cn=alice1978,ou=group,dc=hackthebox,dc=htb
objectClass: posixGroup
objectClass: top
cn: alice1978
userPassword:: e2NyeXB0fSo=
gidNumber: 5000

# ypuffy, hackthebox.htb
dn: sambadomainname=ypuffy,dc=hackthebox,dc=htb
sambaDomainName: YPUFFY
sambaSID: S-1-5-21-3933741069-3307154301-3557023464
sambaAlgorithmicRidBase: 1000
objectclass: sambaDomain
sambaNextUserRid: 1000
sambaMinPwdLength: 5
sambaPwdHistoryLength: 0
sambaLogonToChgPwd: 0
sambaMaxPwdAge: -1
sambaMinPwdAge: 0
sambaLockoutDuration: 30
sambaLockoutObservationWindow: 30
sambaLockoutThreshold: 0
sambaForceLogoff: -1
sambaRefuseMachinePwdChange: 0
sambaNextRid: 1001

# search result
search: 2
result: 0 Success

# numResponses: 9
# numEntries: 8
```

There's something interesting going on with `Alice`'s account.


{% include image.html image_alt="7af88749.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/7af88749.png" %}


We can pass-the-hash with `sambaNTPassword`, using `smbclient`.

### Samba


{% include image.html image_alt="f777316f.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/f777316f.png" %}


Indeed. We are able to view `alice`'s share. Now, let's see what we can get from it.


{% include image.html image_alt="7b1ba80b.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/7b1ba80b.png" %}


I got a copy of `my_private_key.ppk`. It turns out to be `alice`'s private key in the PuTTY format.


{% include image.html image_alt="b0d3e231.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/b0d3e231.png" %}


## Low-Privilege Shell

It's trivial to convert the key to OpenSSH's format with `puttygen`.

```
# puttygen my_private_key.ppk -o alice -O private-openssh-new
```

Once that's done, we can log in to `alice`'s SSH account.


{% include image.html image_alt="a4d7bee3.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/a4d7bee3.png" %}


`user.txt` is at `alice`'s home directory.


{% include image.html image_alt="46da813f.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/46da813f.png" %}


## Privilege Escalation

During enumeration of `alice`'s account, I notice that `~/.ssh/authorized_keys` is missing from her home directory. How the hell did I manage to log in then?

For all things SSH, the best place for consultation is `/etc/ssh/sshd_config`.


{% include image.html image_alt="8a4496b3.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/8a4496b3.png" %}


Hmm. `alice` is getting authorization from somewhere else. This SSH server also support certificate-based authentication.

So, the box is running a PostgreSQL instance at the loopback interface.


{% include image.html image_alt="a5c5d47b.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/a5c5d47b.png" %}


Further digging reveals the database schema is at `bob`'s home directory.


{% include image.html image_alt="ab0e5c61.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/ab0e5c61.png" %}


You know what? I can access the database `sshauth` without password!


{% include image.html image_alt="10e5de4a.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/10e5de4a.png" %}


I'm interested in the `principals` table, especially the one for `root`.


{% include image.html image_alt="d8331ae8.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/d8331ae8.png" %}


All the pieces of the puzzle are falling together. The user certificate authority (CA) signing key is at `/home/userca` and `alice` is able to run `ssh-keygen` as `userca`.


{% include image.html image_alt="344bc838.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/344bc838.png" %}


Here's the game plan.

1. I generate a SSH key pair on my attacking machine.
2. Copy the public key to `YPUFFY`, with `scp`, for CA's signing.
3. Indicate `3m3rgencyB4ckd00r` as the principal in the argument for the signing.
4. Copy the signed public key (which essentially is a certificate) back to my attacking machine.
5. Log in to `YPUFFY` as `root`.
6. Get `root.txt`.

_1. Generate a SSH key pair on my attacking machine_


{% include image.html image_alt="720ad125.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/720ad125.png" %}


_2. Copy the public key to `YPUFFY`, with `scp`, for CA's signing_


{% include image.html image_alt="f767c5ef.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/f767c5ef.png" %}


_3. Indicate `3m3rgencyB4ckd00r` as the principal in the argument for the signing_


{% include image.html image_alt="5e4b9009.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/5e4b9009.png" %}


_4 .Copy the certificate back to my attacking machine_


{% include image.html image_alt="9b8b587b.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/9b8b587b.png" %}


_5. Log in to`YPUFFY` as`root`_


{% include image.html image_alt="05aca881.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/05aca881.png" %}


_6. Get `root.txt`_


{% include image.html image_alt="b5e7f763.png" image_src="/e289230f-cc6d-4f0c-a239-9ad57ee6551a/b5e7f763.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/154
[2]: https://www.hackthebox.eu/home/users/profile/46317
[3]: https://www.hackthebox.eu/
