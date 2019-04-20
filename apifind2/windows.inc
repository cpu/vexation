LPSTR   TYPEDEF DWORD
HANDLE  TYPEDEF DWORD

IMAGE_DOS_HEADER      STRUCT
  e_magic      WORD ?
  e_cblp       WORD ?
  e_cp         WORD ?
  e_crlc       WORD ?
  e_cparhdr    WORD ?
  e_minalloc   WORD ?
  e_maxalloc   WORD ?
  e_ss         WORD ?
  e_sp         WORD ?
  e_csum       WORD ?
  e_ip         WORD ?
  e_cs         WORD ?
  e_lfarlc     WORD ?
  e_ovno       WORD ?
  e_res        WORD 4 DUP(?)
  e_oemid      WORD ?
  e_oeminfo    WORD ?
  e_res2       WORD 10 DUP(?)
  e_lfanew     DWORD ?
IMAGE_DOS_HEADER      ENDS

IMAGE_DATA_DIRECTORY  STRUCT
  VirtualAddress   DWORD ?
  isize            DWORD ?
IMAGE_DATA_DIRECTORY  ENDS

IMAGE_OPTIONAL_HEADER STRUCT
  Magic                   WORD ?
  MajorLinkerVersion      BYTE ?
  MinorLinkerVersion      BYTE ?
  SizeOfCode              DWORD ?
  SizeOfInitializedData   DWORD ?
  SizeOfUninitializedData DWORD ?
  AddressOfEntryPoint     DWORD ?
  BaseOfCode              DWORD ?
  BaseOfData              DWORD ?
  ImageBase               DWORD ?
  SectionAlignment        DWORD ?
  FileAlignment           DWORD ?
  MajorOperatingSystemVersion WORD ?
  MinorOperatingSystemVersion WORD ?
  MajorImageVersion       WORD ?
  MinorImageVersion       WORD ?
  MajorSubsystemVersion   WORD ?
  MinorSubsystemVersion   WORD ?
  Win32VersionValue       DWORD ?
  SizeOfImage             DWORD ?
  SizeOfHeaders           DWORD ?
  CheckSum                DWORD ?
  Subsystem               WORD ?
  DllCharacteristics      WORD ?
  SizeOfStackReserve      DWORD ?
  SizeOfStackCommit       DWORD ?
  SizeOfHeapReserve       DWORD ?
  SizeOfHeapCommit        DWORD ?
  LoaderFlags             DWORD ?
  NumberOfRvaAndSizes     DWORD ?
  DataDirectory           IMAGE_DATA_DIRECTORY 16 dup(<?>)
IMAGE_OPTIONAL_HEADER ENDS

IMAGE_FILE_HEADER     STRUCT
  Machine              WORD ?
  NumberOfSections     WORD ?
  TimeDateStamp        DWORD ?
  PointerToSymbolTable DWORD ?
  NumberOfSymbols      DWORD ?
  SizeOfOptionalHeader WORD ?
  Characteristics      WORD ?
IMAGE_FILE_HEADER     ENDS

IMAGE_NT_HEADERS      STRUCT
  Signature    DWORD ?
  FileHeader   IMAGE_FILE_HEADER <?>
  OptionalHeader IMAGE_OPTIONAL_HEADER <?>
IMAGE_NT_HEADERS      ENDS

IMAGE_SECTION_HEADER  STRUCT
  Name1             DB 8 DUP(?)
  UNION
    PhysicalAddress DD ?
    VirtualSize     DD ?
  ENDS
  SecHdrVirtualAddress    DD ?
  SizeOfRawData     DD ?
  PointerToRawData  DD ?
  PointerToRelocations DD ?
  PointerToLineNumbers DD ?
  NumberOfRelocations  DW ?
  NumberOfLineNumbers  DW ?
  SecHdrCharacteristics DD ?   
IMAGE_SECTION_HEADER  ENDS

IMAGE_EXPORT_DIRECTORY STRUCT
  ImageExportCharacteristics           DWORD      ?
  TimeDateStamp             DWORD      ?
  MajorVersion              WORD       ?
  MinorVersion              WORD       ?
  nName                     DWORD      ?
  nBase                     DWORD      ?
  NumberOfFunctions         DWORD      ?
  NumberOfNames             DWORD      ?
  AddressOfFunctions        DWORD      ?
  AddressOfNames            DWORD      ?
  AddressOfNameOrdinals     DWORD      ?
IMAGE_EXPORT_DIRECTORY ENDS

WIN32_MAX_PATHLEN     EQU 260

FILETIME STRUCT
  dwLowDateTime     DWORD      ?
  dwHighDateTime    DWORD      ?
FILETIME ENDS

WIN32_FIND_DATA STRUCT
  dwFileAttributes      DWORD      ?
  ftCreationTime        FILETIME <>
  ftLastAccessTime      FILETIME <>
  ftLastWriteTime       FILETIME <>
  nFileSizeHigh         DWORD      ?
  nFileSizeLow          DWORD      ?
  dwReserved0           DWORD      ?
  dwReserved1           DWORD      ?
  cFileName             BYTE WIN32_MAX_PATHLEN dup(?)
  cAlternate            BYTE 14 dup(?)
WIN32_FIND_DATA ENDS

INVALID_HANDLE_VALUE  EQU -1
FILE_ATTRIBUTE_NORMAL EQU 80h
OPEN_EXISTING         EQU 3h
GENERIC_READ          EQU 80000000h
GENERIC_WRITE         EQU 40000000h
PAGE_READWRITE        EQU 4h
FILE_MAP_WRITE        EQU 2h
IMAGE_DOS_SIGNATURE   EQU 5A4Dh ; 'MZ' (little endian)
IMAGE_NT_SIGNATURE    EQU 4550h ; 'PE' (little endian)
IMAGE_SUBSYSTEM_WINDOWS_GUI EQU 2h
IMAGE_SUBSYSTEM_WINDOWS_CUI EQU 3h
IMAGE_FILE_MACHINE_I386 EQU 14Ch
IMAGE_SCN_MEM_READ    EQU 40000000h
IMAGE_SCN_MEM_WRITE   EQU 80000000h
IMAGE_SCN_MEM_EXECUTE EQU 20000000h
IMAGE_SCN_CNT_CODE    EQU 00000020h
