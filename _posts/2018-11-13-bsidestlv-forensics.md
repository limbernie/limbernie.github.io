---
layout: post
title: "BSidesTLV: 2018 CTF (Forensics)"
date: 2018-11-13 03:41:35 +0000
last_modified_at: 2018-11-13 04:46:16 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Forensics)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## Background

The 2018 BSidesTLV CTF competition brought together over 310 teams burning the midnight oil to crack our challenges in a bout that lasted for two weeks. You can now enjoy the same pain and suffering, using this easy-to-use, condensed VM that now hosts all our challenges in an easy to digest format. The CTF has five categories:

+ Web (10 challenges)
+ Reverse Engineering (3 challenges)
+ Misc (3 challenges)
+ Forensics (1 challenge)
  1. <a href="#{{ 'Shared Directory' | downcase | replace: ' ', '-'}}">Shared Directory</a>
+ Crypto (2 challenges)

What follows is my humble attempt of cracking the challenges in the **Forensics** category.

## Shared Directory

This is how the challenge looks like.

<a class="image-popup">
![9b9b4ea8.png](/assets/images/posts/bsidestlv-forensics/9b9b4ea8.png)
</a>

There's no hiccup in unzipping `win.zip`.

<a class="image-popup">
![c3475da0.png](/assets/images/posts/bsidestlv-forensics/c3475da0.png)
</a>

The hint is strong in this one. CR and Windows? Microsoft uses `\r\n` or `CRLF` to denote end-of-line.

<a class="image-popup">
![dd53a1da.png](/assets/images/posts/bsidestlv-forensics/dd53a1da.png)
</a>

The creator has peppered the entire file with `CRLF`s. If you look at the modified timestamp `\xDF\xE8\x0D\x0A` at file offset `0x4`, and if you remove the byte `0x0D`, the timestamp then becomes `\xDF\xE8\x0A\x5B` which is _Sun May 27 17:20:31 UTC 2018_.

<a class="image-popup">
![8e6332e2.png](/assets/images/posts/bsidestlv-forensics/8e6332e2.png)
</a>

The OS also becomes Unix, which makes more sense for `.tar.gz`.

Now, let's use `dos2unix` to convert `CRLF` to `LF` in the file.

<a class="image-popup">
![c74ff970.png](/assets/images/posts/bsidestlv-forensics/c74ff970.png)
</a>

We can proceed to extraction.

<a class="image-popup">
![a6ca5007.png](/assets/images/posts/bsidestlv-forensics/a6ca5007.png)
</a>

After extraction, a directory `out` and file `model.json` are present. The `out` directory contains 4999 binaries. The file `model.json` contains an interesting string "FemtoZip"

<a class="image-popup">
![b94935e4.png](/assets/images/posts/bsidestlv-forensics/b94935e4.png)
</a>

Pivoting on "FemtoZip" in Google led me to a GitHub [repository](https://github.com/gtoubassi/femtozip). According to the project description,

> FemtoZip is a "shared dictionary" compression library optimized for small documents that may not compress well with traditional tools such as gzip

Well-played. "Shared Directory"? Should've been "shared dictionary" :laughing:

Following the instructions to build and decompress, this is what I got.

<a class="image-popup">
![8226975e.png](/assets/images/posts/bsidestlv-forensics/8226975e.png)
</a>

The flag is `BSidesTLV{F3mZ1pisTh3B3st}`.
