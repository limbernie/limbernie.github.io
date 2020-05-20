---
layout: post
title: "Lightweight: Hack The Box Walkthrough"
date: 2019-05-12 04:33:41 +0000
last_modified_at: 2019-05-12 04:36:01 +0000
category: Walkthrough
tags: ["Hack The Box", Lightweight, retired]
comments: true
image:
  feature: lightweight-htb-walkthrough.jpg
  credit: annca / Pixabay
  creditlink: https://pixabay.com/en/feather-fluffy-slightly-softness-3092915/
---

This post documents the complete walkthrough of Lightweight, a retired vulnerable [VM][1] created by [0xEA31][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Lightweight is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.119
...
PORT    STATE SERVICE REASON         VERSION
22/tcp  open  ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 19:97:59:9a:15:fd:d2:ac:bd:84:73:c4:29:e9:2b:73 (RSA)
|   256 88:58:a1:cf:38:cd:2e:15:1d:2c:7f:72:06:a3:57:67 (ECDSA)
|_  256 31:6c:c1:eb:3b:28:0f:ad:d5:79:72:8f:f5:b5:49:db (ED25519)
80/tcp  open  http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16
|_http-title: Lightweight slider evaluation page - slendr
389/tcp open  ldap    syn-ack ttl 63 OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
| Subject Alternative Name: DNS:lightweight.htb, DNS:localhost, DNS:localhost.localdomain
| Issuer: commonName=lightweight.htb
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-06-09T13:32:51
| Not valid after:  2019-06-09T13:32:51
| MD5:   0e61 1374 e591 83bd fd4a ee1a f448 547c
|_SHA-1: 8e10 be17 d435 e99d 3f93 9f40 c5d9 433c 47dd 532f
|_ssl-date: TLS randomness does not represent time
```

`nmap` finds `22/tcp`, `80/tcp` and surprise, surprise, `389/tcp` open. At this point in time, my best bet is to start with the `http` service. This is how it looks like.


{% include image.html image_alt="cb5e03fc.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/cb5e03fc.png" %}


## Low-Privilege Shell

Instead of going straight for directories/files enumeration, it pays to explore the site in greater details by carefully reading the instructions.


{% include image.html image_alt="8b104113.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/8b104113.png" %}


If you play your cards correctly, you'll use `10.10.14.2` to login instead.


{% include image.html image_alt="4ac0edad.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/4ac0edad.png" %}


Let's do that.


{% include image.html image_alt="b1f0ac36.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/b1f0ac36.png" %}


## Privilege Escalation

During enumeration of `10.10.14.2`'s account, I used `ldapsearch` to enumerate the LDAP database.

```
[10.10.14.2@lightweight ~]$ ldapsearch -H ldap:// -x -b 'dc=lightweight,dc=htb'
# extended LDIF
#
# LDAPv3
# base <dc=lightweight,dc=htb> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# lightweight.htb
dn: dc=lightweight,dc=htb
objectClass: top
objectClass: dcObject
objectClass: organization
o: lightweight htb
dc: lightweight

# Manager, lightweight.htb
dn: cn=Manager,dc=lightweight,dc=htb
objectClass: organizationalRole
cn: Manager
description: Directory Manager

# People, lightweight.htb
dn: ou=People,dc=lightweight,dc=htb
objectClass: organizationalUnit
ou: People

# Group, lightweight.htb
dn: ou=Group,dc=lightweight,dc=htb
objectClass: organizationalUnit
ou: Group

# ldapuser1, People, lightweight.htb
dn: uid=ldapuser1,ou=People,dc=lightweight,dc=htb
uid: ldapuser1
cn: ldapuser1
sn: ldapuser1
mail: ldapuser1@lightweight.htb
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JDNxeDBTRDl4JFE5eTFseVFhRktweHFrR3FLQWpMT1dkMzNOd2R
 oai5sNE16Vjd2VG5ma0UvZy9aLzdONVpiZEVRV2Z1cDJsU2RBU0ltSHRRRmg2ek1vNDFaQS4vNDQv
shadowLastChange: 17691
shadowMin: 0
shadowMax: 99999
shadowWarning: 7
loginShell: /bin/bash
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/ldapuser1

# ldapuser2, People, lightweight.htb
dn: uid=ldapuser2,ou=People,dc=lightweight,dc=htb
uid: ldapuser2
cn: ldapuser2
sn: ldapuser2
mail: ldapuser2@lightweight.htb
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: top
objectClass: shadowAccount
userPassword:: e2NyeXB0fSQ2JHhKeFBqVDBNJDFtOGtNMDBDSllDQWd6VDRxejhUUXd5R0ZRdms
 zYm9heW11QW1NWkNPZm0zT0E3T0t1bkxaWmxxeXRVcDJkdW41MDlPQkUyeHdYL1FFZmpkUlF6Z24x
shadowLastChange: 17691
shadowMin: 0
shadowMax: 99999
shadowWarning: 7
loginShell: /bin/bash
uidNumber: 1001
gidNumber: 1001
homeDirectory: /home/ldapuser2

# ldapuser1, Group, lightweight.htb
dn: cn=ldapuser1,ou=Group,dc=lightweight,dc=htb
objectClass: posixGroup
objectClass: top
cn: ldapuser1
userPassword:: e2NyeXB0fXg=
gidNumber: 1000

# ldapuser2, Group, lightweight.htb
dn: cn=ldapuser2,ou=Group,dc=lightweight,dc=htb
objectClass: posixGroup
objectClass: top
cn: ldapuser2
userPassword:: e2NyeXB0fXg=
gidNumber: 1001

# search result
search: 2
result: 0 Success

# numResponses: 9
# numEntries: 8
```

You can see that the `crypt`-hashed, `base64`-encoded passwords of `ldapuser1` and `ldapuser2` are exposed. The passwords are close to unbreakable because of the salt and six iteration rounds. Obviously, cracking the hash is not the way to go.

How do we get the passwords then? LDAPv3 uses various authentication methods and simple authentication is where plaintext username and password are sent over the wire, susceptible to network sniffing.


{% include image.html image_alt="3cc96c70.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/3cc96c70.png" %}


You can see that `tcpdump` has the capabilities to basically capture all network traffic even in a low-privileged account, such as the one I'm using.

How do we trigger the authentication then? By going to `status.php` because it took time to load. Something must be going on behind the scenes.


{% include image.html image_alt="a32107ca.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/a32107ca.png" %}


Once the page is loaded, a LDAP request is sent from the page to the LDAP server with the username and password sent in plaintext.


{% include image.html image_alt="e4f1a700.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/e4f1a700.png" %}


We should be able to log in to `ldapuser2`'s account.


{% include image.html image_alt="6f8aeec9.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/6f8aeec9.png" %}


Bingo.

`user.txt` is at `ldapuser2`'s home directory.


{% include image.html image_alt="911fe765.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/911fe765.png" %}


In the same location, there's a password-protected 7z archive as well.


{% include image.html image_alt="9d40ceba.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/9d40ceba.png" %}


I copy the file over to my attacking machine for offline cracking using `base64` like so.

```
[ldapuser2@lightweight ~]$ base64 -w0 backup.7z && echo
```

Copy and paste the `base64` string over to my attacking machine and `base64` decode it back to the file.

```
# echo -n N3q8rycc...BPiBwEwAA | base64 -d > backup.7z
```

Use `7z2john` to generate a hash and send it to John the Ripper for cracking.


{% include image.html image_alt="7bb83fa4.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/7bb83fa4.png" %}


It's the backup of the PHP files used in the site. In `status.php`, you'll find the password of `ldapuser1`.


{% include image.html image_alt="e6457731.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/e6457731.png" %}


Awesome.


{% include image.html image_alt="c743f039.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/c743f039.png" %}


The `openssl` here has super powers! It can basically do anything.


{% include image.html image_alt="494f80c4.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/494f80c4.png" %}


With that in mind, let's encrypt/decrypt `/etc/sudoers` to `/tmp`, include `ldapuser1` to `sudo` list with some `sed` magic, and then encrypt/decrypt it back to `/etc/sudoers`.


{% include image.html image_alt="3d242375.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/3d242375.png" %}


Awesome. We can now `sudo` ourselves as `root` and retrieve `root.txt`.


{% include image.html image_alt="e67321c4.png" image_src="/1da16dfc-94c0-4a64-be4b-e44cac3e691c/e67321c4.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/166
[2]: https://www.hackthebox.eu/home/users/profile/13340
[3]: https://www.hackthebox.eu/
