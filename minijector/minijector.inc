;
; Required kernel32.dll Win32 API functions
;
extrn   ExitProcess:PROC
extrn   FindFirstFileA:PROC
extrn   FindNextFileA:PROC
extrn   lstrcpy:PROC
extrn   CreateFileA:PROC
extrn   GetFileSize:PROC
extrn   CreateFileMappingA:PROC
extrn   MapViewOfFile:PROC
extrn   UnmapViewOfFile:PROC
extrn   CloseHandle:PROC
