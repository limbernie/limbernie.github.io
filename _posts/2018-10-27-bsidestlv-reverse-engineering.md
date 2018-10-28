---
layout: post
title: "BSidesTLV: 2018 CTF (Reverse Engineering)"
date: 2018-10-28 00:28:28 +0000
category: CTF
tags: [BSidesTLV]
comments: true
image:
  feature: bsidestlv.jpg
---

This post documents my attempt to complete [BSidesTLV: 2018 CTF (Reverse Engineering)](https://www.vulnhub.com/entry/bsidestlv-2018-ctf,250/). If you are uncomfortable with spoilers, please stop reading now.
{: .notice}

<!--more-->

### Background

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

This means that we can't even find the `main` function.

<a class="image-popup">
![6ae27d29.png](/assets/images/posts/bsidestlv-reverse-engineering/6ae27d29.png)
</a>

The entry point is too small.

Using GDB, we can place a breakpoint at `0x0` and run the file. Of course, GDB will complain that it can't place the breakpoint. But when we run `info file` again, the entry point of `infected` is resolved.

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

Woohoo. We are now in the territory of `main`. We can proceed to reverse engineering now.

To be honest, I love password login challenges in CTFs, especially those in an executable, because eventually the program has to compare the input to the actual password.

After some stepping through, this is what I've discovered:

+ The program picks out eight hexstrings from a list of 207 hexstrings in the executable
+ Every entered password is compared to the eight hexstrings, each copied to a buffer using `strncpy`
+ The flag is the `base64` decoding of the concatenation of the eight hexstrings.

Armed with the insight, we can make use of `ltrace` to expose the hexstrings during the comparison.

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

Since the challenge is about .NET and intermediate language (or IL), we have to rely on [dnSpy](https://github.com/0xd4d/dnSpy), a .NET debugger and assembly editor. There's alot to like about dnSpy—the default interface is dark-themed—who can say no to that? The instruction to install, configure, and use dnSpy is beyond the scope of this write-up.

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

You can see that the assembly will not run because either it detects an attached debugger or a generated random number is always less than 312.

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

The advantage of .NET asssembly is that you can easily edit IL code and re-assemble it with a tool like dnSpy. Let's edit the code to save the dynamic assembly so that we can view the IL instructions in `gimmedeflag`.

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

The `gimmedeflag` method, even if ran, will not return anything because it'll always throw a `null`. But, since we are dealing with .NET assembly, we can re-purpose the original assembly to include a corrected `gimmedeflag` method, load the orginal assembly file with `Assembly.LoadFile` to get its `Main` IL as a byte array.

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
