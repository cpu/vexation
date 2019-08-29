---
title: Don't be suspicious
date: "2019-08-29T00:00:00.000Z"
description: Redirecting control-flow back to an infected program's original entry-point.
---

Welcome back! If this is your first visit to VeXation you may want to start at [the beginning][Start].

[Start]: /welcome

# Continued Recap

At the end of the [last post][LastPost] I had completed [`apisafejector`][apisafejector], a self-replicating position independent PE infector virus that avoids hard-coded Win32 API addresses. While `apisafejector` is a real improvement over [earlier][minijector] versions and [iterations][pijector] of the WIP virus it still has one large flaw: infected programs no longer work correctly!

Today I'll describe how I fixed this flaw and updated the virus so that the original program code is executed after propagating the infection.

[LastPost]: /kernel32-dll-exports
[apisafejector]: https://github.com/cpu/vexation/tree/master/apisafejector
[minijector]: https://github.com/cpu/vexation/tree/master/minijector
[pijector]: https://github.com/cpu/vexation/tree/master/pijector

# The problem at hand

One of the steps that `apisafejector` takes in order to get the appended virus code to be executed when an infected program is run is [changing the `AddressOfEntryPoint`][RVAChange] in the infected executable's PE header.

```nasm
; eax -> SecHdrVirtualAddress of .ireloc section, a RVA
mov (IMAGE_NT_HEADERS [ecx]).OptionalHeader.AddressOfEntryPoint, eax
```

["Peering inside the PE"][PEPeering] describes this field as:

> DWORD AddressOfEntryPoint
>
> The address where the loader will begin execution. This is an RVA, and can usually be found in the .text section.

In the case of `apisafejector` the virus stomps an infected program's true `AddressOfEntryPoint` RVA, replacing the one that pointed into the `.text` section with one that points into the `.ireloc` section where the injected virus code is. Importantly the injected virus code never invokes the program's real executable code that lays dormant in the `.text` section.

From a user experience perspective this means infected programs appear broken - they don't do anything when they are run (_except silently infect other executables of course_). This kind of side-effect is unnecessarily destructive and sure to bring attention to the virus prematurely.

[RVAChange]: https://github.com/cpu/vexation/blob/480676904b8fcc39ebeed19846b28491f4e55fa2/apisafejector/apisafejector.asm#L422-L439
[PEPeering]: https://docs.microsoft.com/en-us/previous-versions/ms809762(v=msdn.10)#the-pe-header
[CleanCalcTDump]: https://github.com/cpu/vexation/blob/480676904b8fcc39ebeed19846b28491f4e55fa2/apisafejector/tdump.clean.calc.exe.txt#L41
[InfectedCalcTDump]: https://github.com/cpu/vexation/blob/480676904b8fcc39ebeed19846b28491f4e55fa2/apisafejector/tdump.infected.calc.exe.txt#L41

## Confirmation

To get myself back into the swing of things I verified the application breaking behaviour of `apisafejector` with `tdump`, `td32` and an infected `calc.exe`.

In brief, my process was to:

* Build `apisafejector` without debug symbols using `make`.
* Use `make run` to infect a copy of `calc.exe` by running `apisafejector.exe` in `td32` to completion.
* Use `tdump` to verify `calc.exe` was infected.
* Copy the infected `calc.exe` into a temp directory alongside an uninfected `cdplayer.exe`
* Use `tdump` to verify that the clean `cdplayer.exe` was not infected yet.
* Run the infected `calc.exe`. Nothing appears to happen. No calculator appears.
* Use `tdump` again to show that `cdplayer.exe` has become infected.
* Run `cdplayer.exe` to show that it appears to be broken too. No CD-player UI appears.

`youtube: https://www.youtube.com/watch?v=xBaSQWOEN5w`

# A direct solution

Suspiciously breaking infected applications is a bug in the virus code that is in dire need of fixing. I went with a straight forward solution to preserving the original function of infected programs:

1. Saving the original `AddressOfEntryPoint` value when an executable is infected.
2. Returning execution to the saved `AddressOfEntryPoint` when the virus is done infecting other programs.

# Saving the original entry RVA

If you remember the previous [delta offets][DeltaOffsets] post then you already know that the virus _code_ and the virus _variables_ are  all in the same PE section. That makes everything self-contained and easier to inject into a new executable.

Another happy side-effect of this approach is that it's easy for one generation of the virus to "pre-populate" variables for the next generation of the virus. When the executing virus code copies itself into the `.ireloc` section of the target executable it will copy its variables with their current values in-tact.

Crucially this means that if the virus saves the original `AddressOfEntryPoint` value of a victim program before it injects itself and stomps the entry point then it will be accessible to the injected virus code later on.

[DeltaOffsets]: /delta-offset

# Jumping to the original entry RVA

With the true entry RVA of the infected program accessible the virus code can go about redirecting execution back to the original program by `jmp`ing to it.

In practice there is one extra wrinkle in the plan: the original entry RVA is just that, a **R**elative **V**irtual **A**ddress. It isn't an absolute address that the virus code can `jmp` right to. Instead it's an offset relative to the address the executable was loaded at by the operating system's [loader][Loader].

In order to figure out the absolute address to `jmp` to the virus code needs to be able to find out what address the operating system happened to load the executable that it is running out of (often called the _base address_). I decided to use the win32 [`GetModuleHandleA`][GetModuleHandleA] function exported by `kernel32.dll` to find this. By providing a `NULL` value for the `lpModuleName` argument `GetModuleHandleA` returns the base address of the executing `.exe`.

The [last VeXation post][LastPost] laid the ground work for reliably calling exported `kernel32.dll` functions from the virus code which made it straight-forward to use `GetModuleHandleA` to find the executable's base address. By combining the base address with the saved original entry RVA the virus code has an absolute address to `jmp` to so the infected program can start to run normally.

[Loader]: https://en.wikipedia.org/wiki/Loader_(computing)
[GetModuleHandleA]: https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea

# Complete Assembly

To start working on a solution to the entry point problem I used the [`apisafejector` project code][apisafejector] as a base, copying it into a new directory called [`epjector`][epjector] (short for _"entry-point injector"_ I guess?) and renaming files/includes accordingly. The majority of my changes are in [`epjector.asm`][epjector.asm].

To begin with I added two new variables to the `_data` label at [the end of the virus code][DataSection] to save entry point RVAs. `DD` is "define double word" and results in a 4 byte variable, matching the size of the `DWORD AddressOfEntryPoint` PE header field.

```nasm
; Original entry-point of to-be infected .exe (or null in generation 0)
originalEntryPoint  DD 0

; Address we return control flow to after infecting (copy of original entry
; point)
savedEntryPoint     DD 0
```

Next I updated the [`@@analyzepe` code][AnalyzePE] to copy the `AddressOfEntryPoint` value of the PE file being considered for infection into the `originalEntryPoint` variable before it is overwritten (respecting the delta offset in `ebp` of course).

```nasm
; At this point we've decided we have found a valid i386 PE and we can
; analyze it for infection.
@@analyzepe:
  ; Copy the original entrypoint address somewhere safe
  mov ecx, (IMAGE_NT_HEADERS [eax]).OptionalHeader.AddressOfEntryPoint
  mov [ebp + originalEntryPoint], ecx
```

To populate `savedEntryPoint` I added some new logic at the very [start of the virus code][SaveOEP] immediately after calculating the delta offset:

```nasm
; If this is not generation 0 then the originalEntryPoint variable will have
; been set when the currently executing PE was infected. We need to stash that
; somewhere we can JMP to later. We'll be writing over originalEntryPoint when
; we find a target to infect and propagate another generation.
@@saveoep:
    mov eax, [ebp + originalEntryPoint]
    mov [ebp + savedEntryPoint], eax
```

The last task is refactoring the code labelled [`findfirst`][FindFirst] and [`findnext`][FindNext] to find the correct absolute address to `jmp` to using the `savedEntryPoint` RVA when there are no more `.exe`s to infect.

Previously if `FindFirstFileA` returned `INVALID_HANDLE_VALUE` (`-1`) or if `FindNextFileA` returned 0 then the virus code would `jmp` to the `error` label to exit the process. I refactored the `epjector` version of this logic to instead `jmp` to a `@@nofirst` or `@@nonext` label that invokes `CALL_OEP`. For example:

```nasm
@@nofirst:
  CALL_OEP
```

In generation 0 things are slightly different than in subsequent generations. Generation 0 has no "original" functionality to return execution to after infection. For all other generations the `savedEntryPoint` variable holds the RVA that the operating system loader would have used if the program wasn't infected.

I chose to implement finding the absolute address for the saved entry-point RVA and jumping to it as a macro called `CALL_OEP`, [defined in `macros.inc`][macros.inc]. 

The macro checks the delta offset stored in `ebp` to decide if the currently executing virus code is generation 0 or not. If it is generation 0 then the macro evaluates to being the same as the old `apisafejector` behaviour, a `jmp` to the `error` label. For generations 1+ the macro evaluates to code that will `jmp` to the correct absolute address using the `savedEntryPoint`.

```nasm
; CALL_OEP is a macro for calling the savedEntryPoint of the
; infected EXE. If called in generation 0 it is equivalent to
; a jmp to the error label because there is no saved entry
; point. When called in generation 1 the GetModuleHandleA API
; function from kernel32.dll is used to find the absolute
; address with the savedEntryPoint RVA.
CALL_OEP MACRO
    LOCAL @@notgenzero
    LOCAL @@genzero
    ; Use EBP to decide if this is gen > 0
    cmp ebp, 0h
    je @@genzero
@@notgenzero:
    ; When it isn't gen0 we need to jmp to OEP
    ; First calculate the base address of the infected PE
    CALL_RUNTIME_API GetModuleHandleA, <0h>
    ; Then add the saved OEP
    add eax, [ebp + savedEntryPoint]
    ; Bye bye! Give control to the non-viral code.
    jmp eax
@@genzero:
    ; When it is gen0 we don't have an OEP to
    ; jmp to. Instead just jmp to error and ExitProcess.
    jmp error
ENDM
```

[epjector]: https://github.com/cpu/vexation/tree/master/epjector
[epjector.asm]: https://github.com/cpu/vexation/tree/master/epjector/epjector.asm
[DataSection]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/epjector.asm#L605-L661
[AnalyzePE]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/epjector.asm#L322-L327
[SaveOEP]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/epjector.asm#L47-L53
[FindFirst]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/epjector.asm#L192-L209
[FindNext]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/epjector.asm#L224-L240
[macros.inc]: https://github.com/cpu/vexation/blob/ef1c6bc24bcd4951db7bc784c4c672f6cd788981/epjector/macros.inc#L82-L106

# A more subtle virus

I repeated the same process I used [to confirm the `apisafejector` behaviour](http://localhost:8000/entry-points/#confirmation) to verify that `epjector` successfully hides the fact that programs are infected by preserving their original behaviour.

For `epjector` the process was to:

* Build `epjector` without debug symbols using `make`.
* Use `make run` to infect a copy of `calc.exe` by running `epjector.exe` in `td32` to completion.
* Use `tdump` to verify `calc.exe` was infected.
* Copy the infected `calc.exe` into a temp directory alongside an uninfected `cdplayer.exe`
* Use `tdump` to verify that the clean `cdplayer.exe` was not infected yet.
* Run the infected `calc.exe`. This time the calculator UI **does appear**!
* Use `tdump` again to show that `cdplayer.exe` has become infected.
* Run `cdplayer.exe`. It also works as intended and the CD player UI appears.

`youtube: http://www.youtube.com/watch?v=OuiVskD6PSo`

# Conclusion

It has taken six posts (!) but I've finally arrived at an acceptable skeleton for
a PE file infector virus. It is definitely not a stealthy or sophisticated virus
but it:

* Successfully self-propagates within a directory.
* Doesn't hard-code any win32 API addresses.
* Doesn't break the infected program.

There are a few directions I have in mind for future posts:

* Building out a payload. The virus needs to **do** something besides propagate itself.
* Improving the infection strategy. The virus should recurse outside of the current directory.
* Discussing AV. I'd like to summarize the most glaring "stealth" problems with the current virus and share some results from running AV against it as-is.

As always, I would love to hear feedback about this project. It would also be useful to know if one of the above directions interests you more than others. Feel free to drop me a line on twitter ([@cpu][twitter]) or by email ([daniel@binaryparadox.net][email]).

[twitter]: https://twitter.com/cpu
[email]: mailto://daniel@binaryparadox.net
