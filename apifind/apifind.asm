;
; (C) CPU - 20-04-2019
;
; apifind.asm is a stand-alone example of an x86 assembly
; program that finds the address of the kernel32.dll 
; GetProcAddress export at runtime without hardcoding ordinals
; or memory addresses.
;
; As a demo the GetProcAddress export is used to find the address
; of kernel32.dll's FindFirstFileA function.
;
; To find the kernel32.dll address it uses the same technique
; as described in 29A 0x4 - "Retrieving API's Addresses" (SIC)
; by LethalMind.
;
; It avoids using the PEB approach that is often favoured by
; more modern Win 2k/NT viruses because it doesn't work on Win95!
;
.386
warn pro
locals
.model flat, stdcall
assume fs:nothing

include windows.inc

; PE Section alignment. We only use this hardcoded value for
; finding the base address of kernel32.dll. It seems like a safe
; assumption that this DLL is always present with the standard
; alignment.
PE_SECTION_ALIGNMENT EQU 10000h

; One "normal" import.
extrn ExitProcess:PROC

; For the functions we're resolving at runtime we need to add
; our own PROCDESCs so we can get type checking and stdcall arg
; passing when using raw function pointers.
procGetProcAddress PROCDESC stdcall baseAddr:DWORD,name:DWORD
procFindFirstFileA PROCDESC stdcall fileName:DWORD,findData:DWORD

; Some normal vars. In the virus code version these will have 
; to be in the .code section and referenced with the delta offset.
.data
  ; Base address of kernel32.dll found at runtime
  kernel32Base DD 0
  ; The null terminated string we'll match for in kernel32.dll's 
  ; exported function name table to bootstrap other apis.
  szGetProcAddress  DB "GetProcAddress",0
  ; Space to hold the address of GetProcAddress
  GetProcAddress DD 0
  ; The name of a kernel32.dll function we want to resolve at runtime
  ; with GetProcAddress.
  szFindFirstFileA DB "FindFirstFileA",0
  ; Space to hold the address of FindFirstFileA
  FindFirstFileA DD 0

  ; Some arguments to use with FindFirstFileA
  findFilter BYTE 2ah,2eh,65h,78h,65h,0h ; *.exe\0
  findData WIN32_FIND_DATA <0>
  findHandle HANDLE 0
.code
start:

; First we need to find kernel32.dll's base address. We can take advantage
; of the fact that the kernel calls the program entrypoint to do this. 
; Since the kernel CreateProcess function called this program's entrypoint
; the return address on the top of the stack will be somewhere in kernel32.dll
; address space and we can search from there for the start of a PE header to get
; the base kernel32.dll address.
;
; NOTE(@cpu): One _disadvantage_ of this technique is it only works if the virus
;             code is executed before the host program code. For more fancy
;             entrypoint obfuscation this will need to be revisited.
@@findkernel32:
  ; Put the dword value from the top of the stack into esi. This is the return
  ; address for the kernel32.CreateProcess function call one frame above us.
  mov esi, dword ptr [esp]
  ; We know the DLL is section aligned so clear out the lower byte of ESI to
  ; begin the search at the section start.
  and esi, 0FFFF0000h
@@findpe:
  ; If ESI points at the value 'MZ' it indicates the section contains
  ; a PE executable and we know its the base addr of kernel32.dll
  cmp word ptr (IMAGE_DOS_HEADER [esi]).Magic, IMAGE_DOS_SIGNATURE
  je @@findgetprocaddr
  ; Otherwise move back by the section alignment and try checking 
  ; for the DOS header magic bytes again.
  sub esi, PE_SECTION_ALIGNMENT
  jmp @@findpe
; Otherwise we found the kernel base address in ESI. Now we need to find the
; kernel32 GetProcAddress API function pointer. We can use this to bootstrap all
; of the other required APIs without hardcoding any offsets.
@@findgetprocaddr:
  ; Save the Kernel32.dll base addr
  mov [kernel32Base], esi
  mov eax, esi

  ; Advance past the end of the IMAGE_DOS_HEADER structure to the
  ; IMAGE_NT_HEADERS
  add esi, (IMAGE_DOS_HEADER [esi]).e_lfanew

  ; Copy the RVA for the first DataDirectory from the PE header. The first
  ; DataDirectory is always the Export table DataDirectory. How convenient!
  mov ebx, (IMAGE_NT_HEADERS [esi]).OptionalHeader.DataDirectory.VirtualAddress
  ; The data directory virtual address is an offset so we need to add the
  ; kernel32 base address to it
  add ebx, eax

  ; Now it's a matter of finding the index of the AddressOfNames entry
  ; that matches GetProcAddress. We can use the learned index to find the
  ; GetProcAddress ordinal which will let us find the GetProcAddress 
  ; function RVA.
  ;
  ; In a high level pseudocode, this is:
  ;
  ; for i = 0; i < numExportedFuncs; i++ {
  ;   if AddressOfNames[i] == "GetProcAddress" {
  ;     return i
  ;   }
  ; }
  ;
  ; Zero the index counter to begin the loop
  xor edx, edx
@@checkexportname:
  ; Clear anything left in esi
  xor esi, esi
  ; Put the base AddressOfNames address into esi
  mov esi, (IMAGE_EXPORT_DIRECTORY [ebx]).AddressOfNames
  ; Offset esi by the edx-th name pointer to get the RVA
  add esi, edx
  ; Adjust by kernel32.dll base
  add esi, eax
  ; Deref the pointer to the RVA for the edx-th name
  mov esi, [esi]
  ; Adjust by kernel32.dll base, and use the name address as the
  ; left side of the compare.
  add esi, eax
  ; The right side of the compare is the getProcAddrName string
  lea edi, [szGetProcAddress]
  ; Compare 16 bytes - the length of getProcAddrName and a null byte.
  mov ecx, 0Fh
  ; Save esi so if the string matches we aren't one past the match.
  push esi
    repz cmpsb
  pop esi
  ; If the compare is zero we found the AddressOfNames entry for GetProcAddress
  ; and can move on to finding the function pointer.
  jz @@findordinal
  ; Otherwise we need to move forward one AddressOfNames entry (4 bytes)
  ; and try the compare again.
  add edx, 4h
  jmp @@checkexportname

; At this point esi points to a match for getProcAddrName 
; and edx is the byte offset into AddressOfNames that matched.
;
; To map from the offset in AddressOfNames to the offset in 
; AddressOfNameOrdinals we need to do some quick math.
;
; AddressOfNames entries are DWORDs while AddressOfNameOrdinals entries 
; are WORDs so to convert the AddressOfNames offset to an 
; AddressOfNameOrdinals offset we need to divide the offset by two.
;
@@findordinal:
  ; A shift and rotate to the right by 1 is a cheap divide by 2.
  shr edx, 01h
  ; Get the RVA for the AddressOfNameOrdinals array
  mov esi, (IMAGE_EXPORT_DIRECTORY [ebx]).AddressOfNameOrdinals
  ; Offset by the updated byte offset
  add esi, edx
  ; Adjust by kernel32.dll base
  add esi, eax
  ; Read the 2 byte ordinal for GetProcAddress
  movzx edx, word ptr [esi]

; edx now holds the ordinal for GetProcAddress and we can use that
; as the offset to find the function pointer.
;
; To get an offset into AddressOfFunctions using the ordinal we need
; to multiply the ordinal index by 4 because each AddressOfFunction entry is
; a DWORD.
@@findfunc:
  ; A shift and rotate to the left by 2 is a cheap multiply by 4.
  shl edx, 02h
  ; Get the RVA for the AddressOfFunctions array
  mov esi, (IMAGE_EXPORT_DIRECTORY [ebx]).AddressOfFunctions
  ; Offset by the updated byte offset
  add esi, edx
  ; Adjust by kernel32.dll base
  add esi, eax
  ; Read the function pointer RVA for GetProcAddress
  mov esi, [esi]
  ; Adjust by kernel32.dll base
  add esi, eax

; Woohoo. esi now finally holds the pointer to GetProcAddress in 
; kernel32.dll. Now we can bootstrap our win32 APIs!
  mov [GetProcAddress], esi

; Let's find the address of the FindFirstFileA function
; using GetProcAddress!
@@findRequiredAPI:
  ; Put the kernel32.dll base address in ebx
  mov ebx, [kernel32Base]
  ; Put the offset of the null terminated string with the
  ; required API name into ecx
  mov ecx, offset szFindFirstFileA
  ; Invoke GetProcAddress( kernel32.dll, szFindFirstFileA )
  mov eax, [GetProcAddress]
  call (type procGetProcAddress) PTR eax, ebx, ecx
  ; If the return was zero there was an error
  or eax, eax
  jz @@exit
  ; Otherwise save the function address into the pointer var
  mov [FindFirstFileA], eax

; Let's try using the FindFirstFileA function to make sure
; this process of finding Win32 API functions is working.
@@tryAPI:
  ; eax == lpFileName argument
  mov eax, offset findFilter
  ; ebx == lpFindFileData argument
  mov ebx, offset findData
  ; edx == resolved address of FindFirstFileA in kernel32.dll
  mov edx, [FindFirstFileA]
  ; Invoke FindFirstFileA( eax, ebx )
  call (type procFindFirstFileA) PTR edx, eax, ebx
  ; If we got an invalid handle from FindFirstFileA that means there were no EXEs 
  ; in the directory.
  cmp eax, INVALID_HANDLE_VALUE
  je @@exit
  ; Otherwise an exe was found and the handle should be saved
  mov [findHandle], eax

; That's the end! All done!
@@exit:
  xor eax, eax
  call ExitProcess, 0h, eax

end start
public start
end
