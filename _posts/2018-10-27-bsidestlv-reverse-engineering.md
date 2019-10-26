---
layout: post
title: "BSidesTLV: 2018 CTF (Reverse Engineering)"
date: 2018-10-28 00:28:28 +0000
last_modified_at: 2018-12-09 08:16:27 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Reverse Engineering)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

## On this post 
{:.no_toc} 

* TOC 
{:toc}

## Background

The 2018 BSidesTLV CTF competition brought together over 310 teams burning the midnight oil to crack our challenges in a bout that lasted for two weeks. You can now enjoy the same pain and suffering, using this easy-to-use, condensed VM that now hosts all our challenges in an easy to digest format. The CTF has five categories:

+ Web (10 challenges)
+ Reverse Engineering (3 challenges)
  1. <a href="#{{ 'Into the rabbit hole' | downcase | replace: ' ', '-'}}">Into the rabbit hole</a>
  2. <a href="#{{ 'hideinplLainsight' | downcase | replace: ' ', '-'}}">hideinplLainsight</a>
  3. <a href="#{{ 'wtflol' | downcase | replace: ' ', '-'}}">wtflol</a>
+ Misc (3 challenges)
+ Forensics (1 challenge)
+ Crypto (2 challenges)

What follows is my humble attempt of cracking the challenges in the **Reverse Engineering** category.

### Into the rabbit hole

This is how the challenge looks like.

<a class="image-popup">
![42b0af23.png](/assets/images/posts/bsidestlv-reverse-engineering/42b0af23.png)
</a>

Let's download the file, unzip it and take a look at the executable.

<a class="image-popup">
![9260d30e.png](/assets/images/posts/bsidestlv-reverse-engineering/9260d30e.png)
</a>

The executable is stripped off its debugging symbols which made reverse engineering harder but not impossible.

<a class="image-popup">
![38f0face.png](/assets/images/posts/bsidestlv-reverse-engineering/38f0face.png)
</a>

This means that we won't even find the `main` function.

<a class="image-popup">
![6ae27d29.png](/assets/images/posts/bsidestlv-reverse-engineering/6ae27d29.png)
</a>

The entry point is too small.

Using GDB, we can place a breakpoint at `0x0` and run the file. Of course, GDB will complain that it can't place the breakpoint. But when we run `info file` again, the entry point of `infected` gets resolved.

<a class="image-popup">
![3364e6aa.png](/assets/images/posts/bsidestlv-reverse-engineering/3364e6aa.png)
</a>

We placed a second breakpoint at the entry point and delete the first breakpoint. We then try to `run` the file again.

<a class="image-popup">
![5b7240b6.png](/assets/images/posts/bsidestlv-reverse-engineering/5b7240b6.png)
</a>

Several instructions down, we will encounter the address of `main`. It's the argument to `__libc_start_main`.

<a class="image-popup">
![697a77c7.png](/assets/images/posts/bsidestlv-reverse-engineering/697a77c7.png)
</a>

We'll place a breakpoint at `0x555555555b90`, delete the second breakpoint, and then `run` the file again.

Woohoo. We are now in the territory of `main`. Let's proceed to reverse engineering.

To be honest, I love password login challenges in CTFs, like those in an executable, because at some point, the program has to compare the input to the actual password.

After some stepping through, this is what I've discovered:

+ The program picks out eight hex-strings from a list of 207 hex-strings in the executable
+ Every entered password gets compared to the eight hex-strings, each copied to a buffer using `strncpy`
+ The flag is the `base64` decoding of the concatenation of the eight hex-strings.

Armed with this insight, we can make use of `ltrace` to tease out the hex-strings during the comparison.

<a class="image-popup">
![b1a4ea59.png](/assets/images/posts/bsidestlv-reverse-engineering/b1a4ea59.png)
</a>

<a class="image-popup">
![abcae88b.png](/assets/images/posts/bsidestlv-reverse-engineering/abcae88b.png)
</a>

The flag is:

```
BSidesTLV{We_gonna_run_run_run_to_the_cities_of_the_future,_take_what_we_can_and_bring_it_back_home._So_take_me_down_to_the_cities_of_the_future,_everybody's_happy_and_I_feel_at_home.}
```

### hideinplLainsight

This is how the challenge looks like.

<a class="image-popup">
![f36a1700.png](/assets/images/posts/bsidestlv-reverse-engineering/f36a1700.png)
</a>

Since the challenge is about .NET and intermediate language (or IL), we have to rely on [dnSpy](https://github.com/0xd4d/dnSpy), a .NET debugger and assembly editor. There's a lot to like about dnSpy—the default interface is dark-themed—who can say no to that? The instruction to install, configure, and use dnSpy, however, is beyond the scope of this write-up.

First, we download the file and confirm that it's indeed a .NET assembly.

<a class="image-popup">
![d6dfe204.png](/assets/images/posts/bsidestlv-reverse-engineering/d6dfe204.png)
</a>

Let's analyze the assembly with dnSpy.

<a class="image-popup">
![dnspy_Sanchez.png](/assets/images/posts/bsidestlv-reverse-engineering/dnspy_Sanchez.png)
</a>

The following is the C# code for the Sanchez class.

<div class="filename"><span>Sanchez</span></div>

```c#
using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace wabbalubbadubdub
{
  // Token: 0x02000002 RID: 2
  public class Sanchez
  {
    // Token: 0x06000001 RID: 1 RVA: 0x00002048 File Offset: 0x00000248
    public static void Main(string[] args)
    {
      if (Debugger.IsAttached)
      {
        Console.WriteLine("Sometimes science is a lot more art than science. A lot of people don't get that.");
        Console.ReadKey();
        return;
      }
      if (new Random(Guid.NewGuid().GetHashCode()).Next(312) < 312)
      {
        return;
      }
      byte[] il = new byte[]
      {
        32, 70, 76, 69, 127, 10, 22, 11, 22, 12, 32, 0, 62, 0, 2, 13,
        32, 0, 0, 0, 1, 19, 4, 32, 0, 64, 4, 0, 19, 5, 22, 19, 6, 32,
        0, 1, 1, 2, 19, 7, 22, 19, 8, 43, 49, 17, 8, 31, 11, 48, 15,
        3, 17, 8, 3, 142, 105, 93, 145, 3, 142, 105, 88, 210, 43, 8,
        3, 17, 8, 3, 142, 105, 93, 145, 19, 9, 2, 17, 8, 2, 17, 8, 145,
        17, 9, 97, 210, 156, 17, 8, 23, 88, 19, 8, 17, 8, 2, 142, 105,
        50, 200, 6, 7, 54, 18, 9, 8, 54, 14, 17, 4, 17, 5, 54, 8, 17,
        7, 17, 6, 54, 2, 20, 122, 2, 42
      };
      byte[] array = new byte[]
      {
        164, 153, 215, 218, 173, 153, 155, 124, 233, 197, 242, 65,
        71, 102, 44, 32, 88, 65, 109, 107, 44, 42, 111, 10, 67, 97,
        111, 119, 42, 90, 68, 51, 117
      };
      byte[] ilasByteArray = Assembly.GetExecutingAssembly().GetTypes()[0].GetMethods()[0].GetMethodBody().GetILAsByteArray();
      AssemblyName assemblyName = new AssemblyName();
      assemblyName.Name = "CitadelOfRicks";
      AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Run);
      AppDomain.CurrentDomain.UnhandledException += delegate(object x, UnhandledExceptionEventArgs y)
      {
        Console.WriteLine("Arrrrgh This is an unrecoverable exception, I need to remove this code somehow");
      };
      TypeBuilder typeBuilder = assemblyBuilder.DefineDynamicModule("DoofusRick").DefineType("J19Zeta7");
      MethodBuilder methodBuilder = typeBuilder.DefineMethod("gimmedeflag", MethodAttributes.FamANDAssem |     MethodAttributes.Family | MethodAttributes.Static | MethodAttributes.HideBySig, CallingConventions.Standard, typeof(byte[]), new Type[]
      {
        typeof(byte[]),
        typeof(byte[])
      });
      SignatureHelper localVarSigHelper = SignatureHelper.GetLocalVarSigHelper();
      for (int i = 0; i < 8; i++)
      {
        localVarSigHelper.AddArgument(typeof(uint));
      }
      localVarSigHelper.AddArgument(typeof(int));
      localVarSigHelper.AddArgument(typeof(byte));
      methodBuilder.SetMethodBody(il, 4, localVarSigHelper.GetSignature(), null, null);
      object obj = typeBuilder.CreateType().GetMethods()[0].Invoke(null, new object[]
      {
        array,
        ilasByteArray
      });
      Console.WriteLine(Encoding.ASCII.GetString((byte[])obj));
      Console.ReadKey();
    }
  }
}
```

You can see that the assembly will not run because either it detects an attached debugger or a generated random number that's always less than 312. We need to remove these offending logic.

```c#
if (Debugger.IsAttached)
{
    Console.WriteLine("Sometimes science is a lot more art than science. A lot of people don't get that.");
    Console.ReadKey();
    return;
}

if (new Random(Guid.NewGuid().GetHashCode()).Next(312) < 312)
{
    return;
}
```

Moving along the rest of the code, you can see that it's using `System.Reflection.Emit` to dynamically write another assembly `CitadelOfRicks`, which contains one module `DoofusRick`, which in turn contains a custom type `J19Zeta7`, which has one method `gimmedeflag`. The body of the method `gimmedeflag` is in the byte array `il`. The byte array contains the necessary IL instructions to run the method.

The method `gimmedeflag` takes in two `byte[]` parameters and returns a `byte[]`. It uses eight local variables. To run the method, supply `array` and `ilasByteArray` as the arguments.

The advantage of .NET assembly is that you can edit IL code and re-assemble it with a tool like dnSpy. Let's edit the code—remove the offending logic above, and save the dynamic assembly so that we can view the IL instructions in `gimmedeflag`.

```c#
AssemblyName assemblyName = new AssemblyName();
assemblyName.Name = "CitadelOfRicks";

// Change to AssemblyBuilderAccess.Save
AssemblyBuilder assemblyBuilder = AppDomain.CurrentDomain.DefineDynamicAssembly(assemblyName, AssemblyBuilderAccess.Save);
AppDomain.CurrentDomain.UnhandledException += delegate(object x, UnhandledExceptionEventArgs y)
{
  Console.WriteLine("Arrrrgh This is an unrecoverable exception, I need to remove this code somehow");
};
TypeBuilder typeBuilder = assemblyBuilder.DefineDynamicModule("DoofusRick").DefineType("J19Zeta7");
MethodBuilder methodBuilder = typeBuilder.DefineMethod("gimmedeflag", MethodAttributes.FamANDAssem | MethodAttributes.Family | MethodAttributes.Static | MethodAttributes.HideBySig, CallingConventions.Standard, typeof(byte[]), new Type[]
{
  typeof(byte[]),
  typeof(byte[])
});
SignatureHelper localVarSigHelper = SignatureHelper.GetLocalVarSigHelper();
for (int i = 0; i < 8; i++)
{
  localVarSigHelper.AddArgument(typeof(uint));
}
localVarSigHelper.AddArgument(typeof(int));
localVarSigHelper.AddArgument(typeof(byte));
methodBuilder.SetMethodBody(il, 4, localVarSigHelper.GetSignature(), null, null);

// Create the type and save the assembly. The filename must be the same as the module name.
typeBuilder.CreateType();
assemblyBuilder.Save("DoofusRick");
```

Open the assembly in dnSpy after it's saved. You can see the `gimmedeflag` method in C#.

<a class="image-popup">
![dnspy_gimmedeflag.png](/assets/images/posts/bsidestlv-reverse-engineering/dnspy_gimmedeflag.png)
</a>

<div class="filename"><span>gimmedeflag</span></div>

```c#
public static byte[] gimmedeflag(byte[] A_0, byte[] A_1)
{
  uint num = 2135247942u;
  uint num2 = 0u;
  uint num3 = 0u;
  uint num4 = 33570304u;
  uint num5 = 16777216u;
  uint num6 = 278528u;
  uint num7 = 0u;
  uint num8 = 33620224u;
  for (int i = 0; i < A_0.Length; i++)
  {
    byte b = (i > 11) ? A_1[i % A_1.Length] : ((byte)((int)A_1[i % A_1.Length] + A_1.Length));
    A_0[i] ^= b;
  }
  if (num > num2 && num4 > num3 && num5 > num6 && num8 > num7)
  {
    throw null;
  }
  return A_0;
}
```

The `gimmedeflag` method, even if ran, will not return anything because it'll always throw a `null`. But, since we are dealing with .NET assembly, we can again re-purpose the original assembly to include a corrected `gimmedeflag` method, load the original assembly file with `Assembly.LoadFile` to get its `Main` IL as a byte array.

Here's the final `Sanchez` class.

<div class="filename"><span>Sanchez</span></div>

```c#
using System;
using System.Diagnostics;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;

namespace wabbalubbadubdub
{
  public class Sanchez
  {
    public static void Main(string[] args)
    {
      byte[] array = new byte[]
      {
        164, 153, 215, 218, 173, 153, 155, 124, 233, 197, 242, 65, 71, 102, 44, 32,
        88, 65, 109, 107, 44, 42, 111, 10, 67, 97, 111, 119, 42, 90, 68, 51, 117
      };

      // Absolute file path to the original assembly
      byte[] ilasByteArray = Assembly.LoadFile("C:\\path\\to\\wabbalubbadubdub.exe").GetTypes()[0].GetMethods()[0].GetMethodBody().GetILAsByteArray();

      Console.WriteLine(Encoding.ASCII.GetString(gimmedeflag(array, ilasByteArray)));
    }

    public Sanchez() {}

    public static byte[] gimmedeflag(byte[] A_0, byte[] A_1)
    {
      uint num = 2135247942u;
      uint num2 = 0u;
      uint num3 = 0u;
      uint num4 = 33570304u;
      uint num5 = 16777216u;
      uint num6 = 278528u;
      uint num7 = 0u;
      uint num8 = 33620224u;
      for (int i = 0; i < A_0.Length; i++)
      {
        byte b = (i > 11) ? A_1[i % A_1.Length] : ((byte)((int)A_1[i % A_1.Length] + A_1.Length));
        A_0[i] ^= b;
      }
      return A_0;
    }
  }
}
```

Let's re-assemble the above as `rickandmorty.exe` and run it.

<a class="image-popup">
![rickyandmorty](/assets/images/posts/bsidestlv-reverse-engineering/rickandmorty.png)
</a>

The flag is `BSidesTLV{Look, Rick, I know IL!}`.

### wtflol

This is how the challenge looks like.

<a class="image-popup">
![dc6d5fa2.png](/assets/images/posts/bsidestlv-reverse-engineering/dc6d5fa2.png)
</a>

This challenge is all about reverse engineering a Microsoft Windows driver; something that's beyond my current skill level. That's not to say I'm giving up. I'll continue to beef up my knowledge in this area until I have something solid to write.

**Update**

My level has increased. I'm back to finish up what I've started.

> Neo: I know Kung-Fu  
> Morpheus: Show me

To tackle this challenge, you'll need all the reverse engineering big guns such as IDA Freeware v7.0, Visual Studio 2017 Community Edition, x64dbg, and Debugging Tools for Windows, also known as WinDbg. The instructions to install, configure, and use them is beyond the scope of this write-up. Nonetheless, here are the links that have helped me:

+ [Windows Driver Kit documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/index)
+ [64-bit Device Driver Development](http://mcdermottcybersecurity.com/articles/64-bit-device-driver-development)

Having the knowledge to load an unknown driver in a virtual machine and perform kernel debugging on the virtual machine goes a long way—it helps you skip a couple of reverse engineering steps.

To debug a kernel driver, first you need to set up the target virtual machine. Assuming your target virtual machine runs 64-bit Windows 10, open an elevated command prompt and run the following commands:

1) Enables loading of test-signed kernel code.  
`bcdedit /set testsigning on`

2) Enables kernel debugging.  
`bcdedit /debug on`

3) Enables debugging over TCP/IP. Remember the key.  
`bcdedit /dbgsettings net hostip:x.x.x.x port:50000`

4) (Optional). Display boot menu to disable driver signature enforcement.  
`bcdedit /set {bootmgr} displaybootmenu on`

Before you reboot your target virtual machine. Open WinDbg in your host computer and press `Ctrl-K` to open the kernel debug options. Enter the key obtained from Step 3 above.

<a class="image-popup">
![kd_option.png](/assets/images/posts/bsidestlv-reverse-engineering/kd_option.png)
</a>

Press OK to start WinDbg.

<a class="image-popup">
![kd.png](/assets/images/posts/bsidestlv-reverse-engineering/kd.png)
</a>

Reboot the target virtual machine.

<a class="image-popup">
![kd_connected.png](/assets/images/posts/bsidestlv-reverse-engineering/kd_connected.png)
</a>

Once the target virtual machine is up and connected to WinDbg, open an elevated command prompt and run the following commands to load the driver:

```
sc create wtflol binpath= c:\windows\system32\drivers\wtflol.sys type= kernel
sc start wtflol
```

<a class="image-popup">
![load_driver.png](/assets/images/posts/bsidestlv-reverse-engineering/load_driver.png)
</a>

Once the target virtual machine has loaded the driver, hit "Break" in WinDbg to suspend it to enter into `kd` or kernel-debug mode.

Here, I'm using the `lmvm` command to display where the driver (or module) is at in kernel memory. If you have been paying attention, you might have noticed `Writing 104400 bytes...` running past WinDbg output window.

<a class="image-popup">
![lmvm_wtflol.png](/assets/images/posts/bsidestlv-reverse-engineering/lmvm_wtflol.png)
</a>

Here, I'm using the `.chain` meta-command to list the loaded WinDbg extension DLLs.

<a class="image-popup">
![kd_writemem.png](/assets/images/posts/bsidestlv-reverse-engineering/kd_writemem.png)
</a>

The target driver has written something to the host machine in a debugger-based target-to-host [attack](https://archive.org/details/Debugger-basedTarget-to-hostCross-systemAttacks-AlexIonescu)!

Well, now that the driver is in the kernel memory, I can dump it out and perform further analysis like searching for decrypted files or decoded strings. I can dump out `wtlol.sys` with the following command.

```
0: kd> .writemem c:\temp\raw fffff801`9cbf0000 (fffff801`9cdf7000-0x1)
```

Let's start with strings analysis.

<a class="image-popup">
![fab4c4f6.png](/assets/images/posts/bsidestlv-reverse-engineering/fab4c4f6.png)
</a>

That's how the driver wrote the file to the host; two `.writemem` depending on the architecture of the host computer. If it's x86, the 32-bit version of `kd.dll` gets written. If it's x86-64, the 64-bit version of `kd.dll` gets written.

<a class="image-popup">
![09d38972.png](/assets/images/posts/bsidestlv-reverse-engineering/09d38972.png)
</a>

Now let's move over to IDA. If you look past the /GS security checks imposed on the driver, you can see that the driver is trying to get the `_DRIVER_OBJECT` of `Null.sys` at `DriverEntry`—the entry point.

<a class="image-popup">
![ida_null.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_null.png)
</a>

You can view the `_DRIVER_OBJECT` structure with the following command:

```
0: kd> dt nt!_DRIVER_OBJECT
   +0x000 Type             : Int2B
   +0x002 Size             : Int2B
   +0x008 DeviceObject     : Ptr64 _DEVICE_OBJECT
   +0x010 Flags            : Uint4B
   +0x018 DriverStart      : Ptr64 Void
   +0x020 DriverSize       : Uint4B
   +0x028 DriverSection    : Ptr64 Void
   +0x030 DriverExtension  : Ptr64 _DRIVER_EXTENSION
   +0x038 DriverName       : _UNICODE_STRING
   +0x048 HardwareDatabase : Ptr64 _UNICODE_STRING
   +0x050 FastIoDispatch   : Ptr64 _FAST_IO_DISPATCH
   +0x058 DriverInit       : Ptr64     long
   +0x060 DriverStartIo    : Ptr64     void
   +0x068 DriverUnload     : Ptr64     void
   +0x070 MajorFunction    : [28] Ptr64     long
```

Speaking of getting the `_DRIVER_OBJECT` of `Null.sys`, who better than WinDbg to retrieve it with a simple command:

```
0: kd> !drvobj Null 2
```

<a class="image-popup">
![kd_drvobj.png](/assets/images/posts/bsidestlv-reverse-engineering/kd_drvobj.png)
</a>

Now, this is where having both the disassembly and kernel debugging of the driver helped speed up analysis by way of compare and contrast.

You can see that the driver sneakily changed the `MAJOR_FUNCTION->IRP_MJ_DEVICE_CONTROL` in the loaded `Null.sys` to one of its function. Now, I can focus on the analysis of one function, `wtflol+0x3740`.

How do I trigger the function at `wtflol+0x3740`? I suspect the driver also implements a Device I/O Control (IOCTL) interface for communicating from user-to-kernel mode. And to invoke the `DeviceIOControl` interface, you have to provide the correct IOCTL code.

Here's the function syntax:

```
BOOL DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  LPVOID       lpInBuffer,
  DWORD        nInBufferSize,
  LPVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  LPDWORD      lpBytesReturned,
  LPOVERLAPPED lpOverlapped
);
```

Meanwhile, back in IDA.

<a class="image-popup">
![ida_ioctl.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_ioctl.png)
</a>

You can see that the function `sub_140003740` is comparing an argument with `0xC07FC004`. Once the argument matches, the logic continues with the preparation of the input buffer.

If I had to guess, I would say that `0xC07FC004` is the IOCTL code. What about the input buffer? Moving along the function `sub_140003740`, you'll see a `memcmp` between two buffers.

<a class="image-popup">
![ida_memcmp.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_memcmp.png)
</a>

The input buffer goes through a transformation before the comparison. Here's what it should look like after transformation.

```
0: kd> db wtflol+0x201a10
fffff801`84a21a10  0e 47 ad a4 e1 13 43 3b-cd 7b da 2f 78 ff 24 33  .G....C;.{./x.$3
fffff801`84a21a20  de 6d b0 cc 1b 14 25 6b-ec 00 00 00 00 00 00 00  .m....%k........
fffff801`84a21a30  2e 53 e6 a6 1d 1a 00 00-d1 ac 19 59 e2 e5 ff ff  .S.........Y....
fffff801`84a21a40  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
fffff801`84a21a50  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
fffff801`84a21a60  00 00 00 00 00 00 00 00-60 fb 67 72 89 bb ff ff  ........`.gr....
fffff801`84a21a70  90 50 6b 81 01 f8 ff ff-99 a2 90 a5 5c 14 72 62  .Pk.........\.rb
fffff801`84a21a80  b4 ed ab 39 99 b3 ed 9b-91 8b 8d 3b 62 72 7a d3  ...9.......;brz.```
```

We can reconstruct the input buffer by subjecting each byte from `0x00` to `0xff` to the transformation algorithm and then comparing it with the above for 25 bytes. If it matches, it must be the input byte.

I've lifted the transformation algorithm and written a program to retrieve the input buffer.

<div class="filename"><span>input.c</span></div>

```c
#include <stdio.h>

unsigned char input[25] =
{
  0x0e, 0x47, 0xad, 0xa4, 0xe1, 0x13, 0x43, 0x3b,
  0xcd, 0x7b, 0xda, 0x2f, 0x78, 0xff, 0x24, 0x33,
  0xde, 0x6d, 0xb0, 0xcc, 0x1b, 0x14, 0x25, 0x6b,
  0xec
};

int main()
{
  unsigned char t = 0;

  for (int i = 0 ; i < 25; i++)
  {
    for (int j = 0; j < 256; j++)
    {
      t = j + 0x3c; t = ~t; --t; t += i; t -= 3;
      t += i; ++t; t -= i; t += 0xce; t -= i; --t;
      t ^= i; t ^= 0x1e; t = ~t; t -= i; t ^= 0x71;
      t += 0xb1; t ^= i; ++t; t ^= i; ++t; t ^= i;
      t -= i; t = ~t; t += 0xe4; t += i; --t; t += i;
      t ^= i; ++t; t = ~t; --t; t = ~t; --t; t ^= 0x36;
      t -= i; t += 0x99; t ^= 0xe6; t -= 0xe0; t ^= 0x39;
      t -= i; t ^= i; ++t; t = ~t; t -= 0xc; t += i;
      t += 0x65; t -= i; t ^= 0xb1; t -= i;

      if (t == input[i])
      {
        printf("0x%02x\n", j);
        break;
      }
    }
  }
}
```
<a class="image-popup">
![a2c1fbc3.png](/assets/images/posts/bsidestlv-reverse-engineering/a2c1fbc3.png)
</a>

With the IOCTL code and input buffer in hand, I can proceed to write the user-mode program that allows me to communicate with the `\\.\NUL` device.

<div class="filename"><span>wtflol.cpp</span></div>

```cpp
#define UNICODE 1
#define _UNICODE 1

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>

#define DEVICE_NAME L"\\\\.\\NUL"
#define IOCTL_CODE 0xC07FC004

unsigned char InputBuffer[25] = {
  0xE5, 0x37, 0x48, 0xD4, 0x4A, 0x97, 0x26, 0x41, 0x12, 0xFB, 0x3F, 0x51,
  0xF7, 0x03, 0xC9, 0xB1, 0x65, 0xD1, 0x21, 0x0C, 0x58, 0x82, 0xA4, 0xC1,
  0x1F
};

int wmain(int argc, wchar_t *argv[])
{
  HANDLE hDevice;
  DWORD returned;
  unsigned char OutputBuffer[1024];

  hDevice = CreateFile(
    DEVICE_NAME,
    GENERIC_READ | GENERIC_WRITE,
    0,
    NULL,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    NULL
	);

  DeviceIoControl(
    hDevice,
    IOCTL_CODE,
    &InputBuffer,
    (DWORD)sizeof(InputBuffer),
    &OutputBuffer,
    (DWORD)sizeof(OutputBuffer),
    &returned,
    NULL
  );

  return 0;
}
```

Once it's compiled and executed in the target virtual machine, a hint appeared on WinDbg.

```
Please continue from here, the pointer to your flag is 00007ffd44fb6010, remember to look at the bigger picture :)
```

Hmm. This looks like the WinDbg memory space, more specifically, the memory space of the loaded WinDbg extension, `kd.dll`!

Now, let's attach x64dbg to WinDbg and inspect what's at `00007ffd44fb6010`. Speaking of debugging a debugger.

<a class="image-popup">
![x64dbg_pointer.png](/assets/images/posts/bsidestlv-reverse-engineering/x64dbg_pointer.png)
</a>

What do we have here?

<a class="image-popup">
![x64dbg_elf.png](/assets/images/posts/bsidestlv-reverse-engineering/x64dbg_elf.png)
</a>

A hidden ELF! Let's dump it out and execute it in Linux and see what we got.

<a class="image-popup">
![e8fcc9ee.png](/assets/images/posts/bsidestlv-reverse-engineering/e8fcc9ee.png)
</a>

WTFLOL. An ASCII art??!!

Remember the hint to look at the bigger [picture](https://github.com/xoreaxeaxeax/REpsych)?

When I load the ELF file in 32-bit IDA, and looking at one of the functions `sub_8048913`, I got a warning dialog saying the graph has more than 1000 nodes.

<a class="image-popup">
![ida_graph.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_graph.png)
</a>

I did as advised and bumped up the graph nodes to 10,000.

<a class="image-popup">
![ida_options.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_options.png)
</a>

The graph overview changed as a result.

<a class="image-popup">
![ida_graph_overview.png](/assets/images/posts/bsidestlv-reverse-engineering/ida_graph_overview.png)
</a>

The flag is `BSidesTLV{Nice_Flag_And_Shit}`.
