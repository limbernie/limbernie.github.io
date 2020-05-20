---
layout: post
title: "Pseudo: A Reversing Challenge"
date: 2019-11-19 02:11:27 +0000
last_modified_at: 2019-11-19 02:11:27 +0000
category: CTF
tags: ["Hack The Box", Pseudo, Reversing, retired]
comments: true
image:
  feature: https://res.cloudinary.com/limbernie/image/upload/img/pseudo-reversing-walkthrough.jpg
---

This post documents my attempt to complete Pseudo, a retired challenge created by [RoliSoft][1], and hosted at [Hack The Box][2]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Do you have enough permissions to get the flag?

## Introduction

The challenge is located [here](https://www.hackthebox.eu/home/challenges/download/18). It's a password-protected archive file.

## Analysis

There is one unknown file in the archive file.


{% include image.html image_alt="79a80293.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/79a80293.png" %}


The file is an ELF for `aarch64` architecture. It probably won't run on my Kali Linux.

```
# file pseudo
pseudo: ELF 64-bit LSB executable, ARM aarch64, version 1 (GNU/Linux), statically linked, no section header
```

In any case, I need to set up Linux in a fully emulated `aarch64` environment since my Kali Linux is a `x86_64` virtual machine.

### QEMU / AArch64 / Ubuntu Server 18.04

Enter QEMU. QEMU is a free and open-source emulator that performs hardware virtualization. I'm making use of Ubuntu's readily-built cloud image, which saves me from installing the operating system from scratch. I also need to bake in a pair of SSH key pair I control since that's the only way to access it.

<div class="filename"><span>cloud.txt</span></div>

```
#cloud-config
users:
  - name: bernie
    ssh-authorized-keys:
      - ssh-rsa AAAAB3Nza...
    sudo: ['ALL=(ALL) NOPASSWD:ALL']
    groups: sudo
    shell: /bin/bash
```

Use `cloud-localds` to build a cloud image with my SSH credentials baked in.

```
# cloud-localds --disk-format=qcow2 cloud.img cloud.txt
```

Running QEMU in a fully emulated environment is slightly complicated because of the various options. Here's my running configuration.

<div class="filename"><span>run.sh</span></div>

```
#!/bin/bash

qemu-system-aarch64 \
-smp 2 \
-m 1024 \
-M virt \
-cpu cortex-a57 \
-bios /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
-nographic \
-device virtio-blk-device,drive=image \
-drive if=none,id=image,file=ubuntu-16.04-server-cloudimg-arm64-uefi1.img,format=qcow2 \
-device virtio-blk-device,drive=cloud \
-drive if=none,id=cloud,file=cloud.img,format=qcow2 \
-device e1000,netdev=net0 \
-netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22
```

I chose to run the configuration on `xterm` for aesthetic reason.


{% include image.html image_alt="09d6146e.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/09d6146e.png" %}


Let's see if I can log in to it.


{% include image.html image_alt="1cac7182.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/1cac7182.png" %}


Awesome. It's like having my own AWS EC2 instance!

### File Analysis

Because the file is stripped of all information (a.k.a "packed"), debugging it straight away won't do us any good. Let's check out the file headers.


{% include image.html image_alt="d635bf9c.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/d635bf9c.png" %}


Here's our clue that it's packed. Notice that it has two ELF magic numbers? And, also "UPX"?


{% include image.html image_alt="35d50b29.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/35d50b29.png" %}


Woohoo, we can unpack it.

### GDB + GEF

I read with interest that [GEF](https://github.com/hugsy/gef) supports ARM, so that's what I'm going to use.


{% include image.html image_alt="f1f1c8cb.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/f1f1c8cb.png" %}


Awesome. Finally we have something! Let's place a breakpoint at the entry point and reverse it away.


{% include image.html image_alt="5c1c5cd4.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/5c1c5cd4.png" %}


Damn, it's `aarch64` alright. I'm in unchartered territory man.

### Locating the `main` function

Because the executable is statically linked, it took a combination of radare2 (`aaaa`) and IDA Pro (call graphs) to locate the `main` function. This is how the `main` function looks like.


{% include image.html image_alt="b4f9742c.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/b4f9742c.png" %}


At the beginning of the function, there's a check for the terminal size. If the column size is less than or equal to 158, an Internet Zoolander meme is printed out.


{% include image.html image_alt="ac09374d.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/ac09374d.png" %}


Here's how the Assembly code for the terminal check looks like. It uses `ioctl`.


{% include image.html image_alt="432c19fc.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/432c19fc.png" %}


Long story short, the instructions in the rounded reactangle are bytecode commands. I managed to decipher three of the commands.

1. 0xEF - Check User
2. 0x80 - Read Password
3. 0xD2 - Check Password

#### 0xEF - Check User

This command uses `malloc` to allocate five bytes of space for the string `USER` and then use `getenv` to get the username of the currently logged on user.

#### 0x80 - Read Password

This command reads the password from `stdin` and transforms each character by subtracting 94 (or `0x5e`) from the character's ordinal number.


{% include image.html image_alt="b83901ae.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/b83901ae.png" %}


#### 0xD2 - Check Password

This command checks the transformed input password with the transformed actual password. The instruction that compares each character is shown below.


{% include image.html image_alt="17b70a33.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/17b70a33.png" %}


The first five registers are shown below.


{% include image.html image_alt="46fbe81b.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/46fbe81b.png" %}


The comparison goes on for sixteen characters. This is the transformed password.


{% include image.html image_alt="3f70b4ec.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/3f70b4ec.png" %}


If the password is incorrect, the program goes into an infinite loop until you terminates it.

#### Decoding the Password

Since we knew how the password is transformed, I wrote a simple shell one-liner to decode it.

```
# for b in $(xxd -p password | sed -r 's/(..)/\1\n/g'); do printf \\$(printf "%o" $((0x$b + 0x5e))); done | rev && echo
~vms_all_the_way
```

Armed with the password, let's get that flag.


{% include image.html image_alt="ea63fa3a.png" image_src="/eef15791-610f-4136-bb1d-55a0e10903f7/ea63fa3a.png" %}


The flags is `HTB{vms_4ll_th3_w4y}`.

:dancer:

[1]: https://www.hackthebox.eu/home/users/profile/1178
[2]: https://www.hackthebox.eu/
