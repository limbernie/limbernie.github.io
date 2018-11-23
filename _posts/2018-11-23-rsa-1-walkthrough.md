---
layout: post
title: "RSA: 1 Walkthrough"
subtitle: "Hand over the Keys"
date: 2018-11-23 14:59:31 +0000
last_modified_at: 2018-11-23 19:25:54 +0000
category: Walkthrough
tags: [VulnHub, RSA]
comments: true
image:
  feature: rsa-1-walkthrough.jpg
  credit: qimono / Pixabay
  creditlink: https://pixabay.com/en/key-keyhole-lock-security-unlock-2114046/
---

This post documents the complete walkthrough of RSA: 1, a boot2root [VM][1] created by Fred Wemeijer, and hosted at [VulnHub][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

[Somewhere](http://www.loyalty.org/~schoen/rsa/) in the Internet.

> In February 2012, two groups of researchers revealed that large numbers of RSA encryption keys that are actively used on the Internet can be cracked because the random numbers used to generate these keys were not random enough.

### Information Gathering

Let’s start with a `nmap` scan to establish the available services in the host.

```
# nmap -n -v -Pn -p- -A --reason -oN nmap.txt 192.168.30.129
...
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.7 (protocol 2.0)
| ssh-hostkey:
|   2048 50:97:eb:98:36:19:57:5d:12:ed:8f:cf:25:62:5d:0d (RSA)
|   256 93:63:87:99:a3:85:f5:bf:c5:9d:9f:3c:58:62:74:a9 (ECDSA)
|_  256 4e:3c:13:17:bf:bb:2a:91:0c:51:f3:85:4f:29:25:20 (ED25519)
80/tcp open  http    syn-ack ttl 64 OpenBSD httpd
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).
```

`nmap` finds `22/tcp` and `80/tcp` open. Let's explore the `http` service first.

### Directory/File Enumeration

Let's see if we can get anything with `wfuzz`.

```
# wfuzz -w /usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://192.168.30.129/FUZZ
********************************************************
* Wfuzz 2.3 - The Web Fuzzer                           *
********************************************************

Target: http://192.168.30.129/FUZZ
Total requests: 950

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000729:  C=301     17 L	      48 W	    443 Ch	  "secrets"

Total time: 1.979362
Processed Requests: 950
Filtered Requests: 949
Requests/sec.: 479.9526
```

We have a `secrets` directory! Let's carry on and see what can we find inside it.

```
# wfuzz -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 http://192.168.30.129/secrets/FUZZ
********************************************************
* Wfuzz 2.3 - The Web Fuzzer                           *
********************************************************

Target: http://192.168.30.129/secrets/FUZZ
Total requests: 4593

==================================================================
ID   Response   Lines      Word         Chars          Payload    
==================================================================

000660:  C=200      9 L	      27 W	   3546 Ch	  "authorized_keys"

Total time: 8.108723
Processed Requests: 4593
Filtered Requests: 4592
Requests/sec.: 566.4269
```

What do we have here? A `authorized_keys`??!!

### Weak RSA Keys

Here's what inside `authorized_keys`.

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC4aOHSLLqN+odwP6G1GdxqJ+I/e1PuX3EbFe64snwy7IFAY8WrPBEsIqEWesOqUXzBI7G6YbiR13nen0XWqZtSn1yBbt1U1a8M+19phOVyo4Awx/wTvpG0EPYLI3H9J5aIOcBntXo6rrpiidMT2jYthUxwKKNUUHkbmLJ6QP9jNpCGZwm2CXO0GLmnFBYbE+53xKbX1DVD7aEiRxi62XhoUsepAsUJOzt4enAp3WuyMz9f8IlWg2BUiUFqlVImNRm9UuuoXhsBItLOcF0DHBgRZN4cFZyZO2x73SOJ5oJIikA3NhJ9rYwrE01HsKwYxhqXB94rM/SBTcJ5c6xes6Er user1@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8i9Nk6Rpd6SlRG/FSPy/M8OXVEO/akLMVaNNJEpejOQ/ekdlTKyBMb4pIEwoKpu+PTTeAzigSNNTNg1TONyK0CsPJ3Uj1oJIrJXYNAFm7kxqQD2pKDIGB0hYj1pwivTLnNhh5cnS7Mnm9ijJPHQ8TEyade9a0v9Ps4BAFEIl9HfjkFm/KDTcQjuBjPTaYgazY5b/EHyfLf2deHeFT4AwzWBa7NdiFKKn5eXComWYIiBcUYWRf0ROd/Tx2aF3Q/hxmbS8ImR4l0ZRdsh6V+gmQzp2eAzNeN9QmJzF2gaDQGZBcKf0gpA8gj0prIcnLFctI6seS+an+N6yUW/bwNBM3 user2@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCQ8ZjTDIcdjaAwSTS1u83FspC6iVba2a1W1jS+UVw+zrxc06xEeTBmdt4p0J9cWCK97pMrBR+dquuLikaSxfI6BxhZY+6MKTnghjI8MiktgpjEOJNA6rfOJzBoIvvQr4E3LJu0gRVDLoSoseDI1Vb9d5AwKQTjGSXGofIpsNzSrwLgu4JKvZAjIfvv/z0bk5VwBmjtJVntlMOBkPyD6ZuGoiWacUH8AFe2lT9h++G6IoIznPQCrIfeKUrIRwbWJWqTumy8RDCKVgTUUYszkq/r1/wAsR1HhZJVon/JczRsZ3ZZL84Zpja0EuYFZKjPgHsewN3pnUEHzWR4b9bCu8dz user3@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7fmeWcwd24gYuSYBgQmO8mr394YsLYvVN46pGPvjEvpLwEXJ/K6JoLYpBX6EKEqj8mvx04YSy5IsZAjYbraRbhtpOmLXRBSOPwnhzUUcBHQANkKpq5pdJrEdD3xzG0CuHF80P0HY9tG/ZXY8J+LJ+LWyL4H0upWRGTcjGm7fZxyRVg2tI2gLPlN3zHpBji92nQ+CXyJPLOFhq8+/fls143tkJ3LissqgOPnLTQkdm6H9XbaWcgLao7ALXEgyXKWMZrMdEbpBiqOsTyBpwpIM3A7iAPu/1QqsPqnwKUbH7z6zn8TbfoPABN+MbvnEmj4jALqhDAnWAaMfq0yUWm5k5 user4@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCge/tLWGuAwvfAZ6jZUVQ+JzhdSlanJduRV8urB94AlP82Rm5y1LMuAy70z0VTE2SNzMG2yqAFGtbfUvkoqfD5WnWG9oHJaoiaJnfxvOLKgNEztTTAdFdMDLHkD3hh4NdxH7aZxQIxHUWtKOhuZ8h73toH7tAkChPkaSO6G79hb2pciCP//TnJfc59Fd5fNQEdROQ8Ekp1mONrqCJAgKJn5BvzXeGAwpxbLpvyJFcW6uTj98GoE9qPSItt5/DPn9oVOX1RgTQjSDqZZq2m1rLtLIs9RIYu/xPTWQ2AsAHvrTCDoNo00ebQPDFz0MzTP8bIyw8ObpoWtdqkEUqi35/r user5@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD00XwLgzJK9Ocwzid87PcnLf7DkZdoggvl624q0vSMKKDNpbj4DNdL8naR5XEoqx2t265AQcUyc2JOQKqMbPuyWdjX6GbYkAa7quWVh0B6W+7qoVLFWmJOi63Rzyrm/TRoHBjJI8jN6bBVoINnm7q0sjJw3xCYEACVR5CM+BLc9sNaVbRmsS1Nu434QeJ4GEiEcdf9LdjvUSZAClAeXcZ6W5hnGg2GCc9Rbo3eFfeXj7A8pk7VZKxhdACnOcYRcAIVUOoPHQUgE4BDTDPKDA5tM7Bf9aGfaIw2j9OnzpYUfen8DGK/LzktpBn10In2R05HXojO6pMrLvJ+81rGqy3x user6@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDlKXFK6oJ4dJtesy2EwTjaq3HpXsvEYraPynrz4zFc1N8KnPiRdZBlX6opIQsxwseUUQXso+0VQ9v4nG3q0/bzKjmFJwg6j16M+P7KndYr1MM8U2tSQ+YOibPJ2FONF9VlPHF3mFviUI+fYGgb1p47Dxj/SQ5s1vuBk4Lf/FTJV3qAEvhwBYA7HysO83SBwSBA+DS64BAWXofZxpOKXET4Q+IKT3d7hIVaFJgWi9q1NRFeHZ0B3AtlrQ+QCppMiZU4aDwl5wGYuV+4QDlkTtQCwilaa2kc5ujbzJhCeww3pMSa0cr5G90a6lwf+GkX+NoumwsoqxgRgj9i1o2BxdKp user7@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC5bur6r9Kq2SB4YGmSFI14K6X8o4LAM6ZQLoMgp52W6NUz2TUFTAXdMkMVBS+dG2wSbcyuZ59Cc6vi2ehQViJmx1vzev2Ejj+bQIPagh6SU/oWRa/KiqlYdzjQsntS5IVQD4WX0kq7zOKDoNLqUhkgmZDBdISN/TRO+iEmKLKowoJlR5EDudLJqY+lZ6wwNtgwG4tMK5c/Czx41pIm1OKw09c23FD0/GGXv0JDBplku+Jjr1CNc+M7QkeVSDXwf8BzkNzWkkQnGxwJQF0ufVuuzkZ9C9Ub0MTvDzMcefiWz3oSkVWz5HeFe2ROS2rBFYUm5M48TrsD5bLYEn6i4LDh user8@rsafun
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUC0NKyGoR1EqOS1suQK0YfitFIt0lFkpwKVYVP4YD86aSiPqpWI6rRsLBevGxOfDdRFHqMmzx4S0tVJfYErs7O7X20xWy6oJJRX67h1QghDZOa8hWEFPSr2qlOhNTvfp9yJbTKvCzStSYN0AR81MiuLn6uSmr6N2LUU02mmA1JmuZlO/ilqU7/fECNY9Dl/hrX7oIqvbpxXZDfxa25PQqy9uTrZe71sCkBkdZ11qj+4hkWPUWrhZgosJXJb61h9QGbmhzte3YyJ6RoEzz3ozFamYBzuyszX/4Ne4juBXzXoD5+En+kFIMnfNk5bVYeD4XG6a8jDDcKzsFrvWZ7zgD user9@rsafun
```

If I've to guess, I'd say this is the concatenation of all the `authorized_keys` from `user1` to `user9`. We know `authorized_keys` typically contains the public component of the SSH RSA key pair.

Here's an example of the SSH public key of `user1`.

<a class="image-popup">
![d2c8c268.png](/assets/images/posts/rsa-1-walkthrough/d2c8c268.png)
</a>

It's apparent that we are dealing with nine RSA 2048-bit key pairs.

Heninger _et al._'s research [paper](https://factorable.net/weakkeys12.extended.pdf) found that _RSA and DSA can fail catastrophically when used with malfunctioning random number generators_. Specifically, if an attacker can find two distinct RSA moduli <i>N<sub>1</sub></i> and <i>N<sub>2</sub></i> that share a prime factor <i>p</i> but have different second prime factors <i>q<sub>1</sub></i> and <i>q<sub>2</sub></i>, then the attacker can easily factor both moduli by computing their greatest common divisor (GCD), p, and dividing to find <i>q<sub>1</sub></i> and <i>q<sub>2</sub></i>. The attacker can then compute both private keys according to this equation:

<a class="image-popup">
![13fac828.png](/assets/images/posts/rsa-1-walkthrough/13fac828.png)
</a>

Given this insight, I wrote a bash script, with `ssh-keygen`, `openssl`, and `python` as the main drivers, to first extract the moduli from the public keys, and then to calculate the GCD (<i>p</i>) among <sup>9</sup>C<sub>2</sub> pairs, follow by their <i>q<sub>1</sub></i> and <i>q<sub>2</sub></i> respectively.

<div class="filename"><span>attack.sh</span></div>

```bash
#!/bin/bash

FILE=authorized_keys

# extract the SSH public keys from FILE
while read line; do
  echo $line > $(cut -d' ' -f3 <<<$line)
done < $FILE

# convert SSH public key to RSA public key
# and then extract the modulus from them
for i in $(seq 1 9); do
  ssh-keygen -e -m PEM -f user${i}@rsafun \
  | openssl rsa \
            -RSAPublicKey_in \
            -in - \
            -modulus \
            -noout \
    | cut -d'=' -f2 > user${i}@rsafun.n
done

# write python script
cat <<EOF > gcd.py
from itertools import combinations
from fractions import gcd
list = []
dict = {}
result = []

# build list
for i in range(9):
  list.append(str(i+1))

# build dictionary
for x in list:
  dict[x] = int(open('user' + x + '@rsafun.n', 'r').read(), 16)

# gcd
for (i, j) in combinations(list, 2):
  p = gcd(dict[i], dict[j])
  if (p != 1):
    result.append((i, j, p, dict[i]/p, dict[j]/p))
    break

print result
EOF

# execute the python script
python gcd.py

# clean up
rm user* gcd.py
```

Let's run `attack.py`.

```
# ./attack.sh
[('2', '4', 154417972435807005071073724522212444390586453823829143415803831059147415798074017502040314003763421243774270757922304211573942665136361376688205405360960917939484579087307177536921412011411703961828583167653172004502917347120641950199480561070177933253465927358617195370782866425595898798109004224439814798057L, 154138482778403634422324585381094741396112094157924874391263694520821571222861298674105765179306306537493034017749692130071107610613435921888902004138078680460276016821583678249932808105907339203963186655685583329163374562641235896970977501756291570424272228689701476926803652905250957577229144433204452772127L, 153278113332014430314822533712203891727299288836706793970670250689211994721080531031391472583116454287125291108401187935648312751844041461411234500935073837231805656247842743814066543045935616374230913460500896653516311833291062554618374636514900539486293512925569339760306744210644153977272176465759656466897L)]
```

We can see that `user2` and `user4` shared a common <i>p</i>. Armed with <i>p</i>, <i>q<sub>1</sub></i>, and <i>q<sub>2</sub></i>, we can reconstruct the RSA private key of `user2` and `user4` with `rsatool.py` like so.

_Reconstruct `user2`'s RSA private key_

```
rsatool.py -o user2.pem -p 154417972435807005071073724522212444390586453823829143415803831059147415798074017502040314003763421243774270757922304211573942665136361376688205405360960917939484579087307177536921412011411703961828583167653172004502917347120641950199480561070177933253465927358617195370782866425595898798109004224439814798057 -q 154138482778403634422324585381094741396112094157924874391263694520821571222861298674105765179306306537493034017749692130071107610613435921888902004138078680460276016821583678249932808105907339203963186655685583329163374562641235896970977501756291570424272228689701476926803652905250957577229144433204452772127
```

_Reconstruct `user4`'s RSA private key_

```
rsatool.py -o user4.pem -p 154417972435807005071073724522212444390586453823829143415803831059147415798074017502040314003763421243774270757922304211573942665136361376688205405360960917939484579087307177536921412011411703961828583167653172004502917347120641950199480561070177933253465927358617195370782866425595898798109004224439814798057 -q 153278113332014430314822533712203891727299288836706793970670250689211994721080531031391472583116454287125291108401187935648312751844041461411234500935073837231805656247842743814066543045935616374230913460500896653516311833291062554618374636514900539486293512925569339760306744210644153977272176465759656466897
```

We can further convert both RSA private keys to the OpenSSH format with `puttygen` to log in to `user2`'s and `user4`'s account respectively.

```
# puttygen user2.pem -o user2 -O private-openssh-new
# puttygen user4.pem -o user4 -O private-openssh-new
```

### Low-privilege Shell

_Log in to `user2`'s account_

<a class="image-popup">
![fc96cf0a.png](/assets/images/posts/rsa-1-walkthrough/fc96cf0a.png)
</a>

_Log in to `user4`'s account_

<a class="image-popup">
![1ce528c6.png](/assets/images/posts/rsa-1-walkthrough/1ce528c6.png)
</a>

### Privilege Escalation

During enumeration of `user2`'s account, I notice that `root` left an encrypted SMIME message for `user2`.

<a class="image-popup">
![22153eb1.png](/assets/images/posts/rsa-1-walkthrough/22153eb1.png)
</a>

Let's decrypt the message.

<a class="image-popup">
![920a4fb4.png](/assets/images/posts/rsa-1-walkthrough/920a4fb4.png)
</a>

This is not your SMIME format. This is the DER format.

<a class="image-popup">
![c74e5f4d.png](/assets/images/posts/rsa-1-walkthrough/c74e5f4d.png)
</a>

From here, we can see that the message is encrypted with RSA. Good thing we have `user2`'s RSA private key.

<a class="image-popup">
![e1a3754f.png](/assets/images/posts/rsa-1-walkthrough/e1a3754f.png)
</a>

With `root`'s password, getting the flag is trivial.

<a class="image-popup">
![7accc2d9.png](/assets/images/posts/rsa-1-walkthrough/7accc2d9.png)
</a>

:dancer:

### Afterthought

Who knew RSA could offer so much fun?

[1]: https://www.vulnhub.com/entry/rsa-1,255/
[2]: https://www.vulnhub.com/
