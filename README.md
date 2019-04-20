# VeXation

Code accompanying [the VeXation development blog](https://log.vexation.com).

All code is written in x86 ASM targetting Borland Turbo Assembler 5.0 and
Windows 95 and is licensed under the GPLv3.

## minijector

Accompanying post: [PE File Infector Basics](https://log.vexation.ca/2019/01/pe-file-infector-basics.html)

Working towards a basic Win95 PE file infector. Minijector will add its own code
to other PE executables in the same directory by appending a new section (named
`.ireloc`).

As described in the accompanying blog post this is not a complete working PE
file infector. The entry point of the infected program is not updated so the
injected copy is fully inert. The virus code is not position independent and
does not find `kernel32.dll` API addresses at runtime.

## pijector

Accompanying post: [A VXers Best Friend: The Delta Offset](https://log.vexation.ca/2019/03/a-vxers-best-friend-delta-offset.html)

"pijector" (position independent (self-in)jector) is a continuation of
Minijector. `pijector.exe` doesn't use a separate data section for its variable
data and instead modifies offsets within the code section. The offsets are
adjusted by the overall delta offset to make the variable references position
independent.

As described in the accompanying blog post this is *still* not a complete
working PE file infector. The entry point of the infected program is not updated
so the injected copy is fully inert. The virus code also does not find
`kernel32.dll` API addresses at runtime.

## apifind & apifind2

Accompanying post: **TBA**.

"apifind" and "apifind2" are stand-alone examples of finding required win32 API
functions at runtime without hardcoding anything. Both find the `kernel32.dll`
base address, locate the `GetProcAddress` export in the DLL, and then
resolve required Windows API function addresses with `GetProcAddress`.

"apifind2" reduces some duplication by providing assembly macros for defining
requiring API variables, describing the API functions/arguments, finding the API
function address, and finally invoking the API function. Start by reading
"apifind" and then compare with "apifind2".
