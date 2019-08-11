;==============================================================================
;
; PE LIBRARY - Special Lite Version For Dll2Def
;
;==============================================================================
.686
.MMX
.XMM
.model flat,stdcall
option casemap:none
include \masm32\macros\macros.asm

;DEBUG32 EQU 1
;IFDEF DEBUG32
;    PRESERVEXMMREGS equ 1
;    includelib M:\Masm32\lib\Debug32.lib
;    DBG32LIB equ 1
;    DEBUGEXE textequ <'M:\Masm32\DbgWin.exe'>
;    include M:\Masm32\include\debug32.inc
;ENDIF

include windows.inc

include user32.inc
includelib user32.lib

include kernel32.inc
includelib kernel32.lib

include PELite.inc

;------------------------------------------------------------------------------
; Prototypes for internal use
;------------------------------------------------------------------------------
PESignature             PROTO :DWORD
PEJustFname             PROTO :DWORD, :DWORD

PEDwordToAscii          PROTO :DWORD, :DWORD
PE_SetError             PROTO :DWORD, :DWORD

PUBLIC PELIB_ErrorNo



.CONST



.DATA
PELIB_ErrorNo               DD PE_ERROR_NO_HANDLE ; Global to store error no
DEFLIBRARY                  DB 'LIBRARY ',0
dwLenDEFLIBRARY             DD ($-DEFLIBRARY)-1
DEFEXPORTS                  DB 'EXPORTS',13,10,0
dwLenDEFEXPORTS             DD ($-DEFEXPORTS)-1
DEFINDENT                   DB '    ',0
dwLenDEFINDENT              DD ($-DEFINDENT)-1
DEFCRLF                     DB 13,10,0
dwLenDEFCRLF                DD ($-DEFCRLF)-1

.CODE
PE_ALIGN
;------------------------------------------------------------------------------
; PE_OpenFile - Opens a PE file (exe/dll/ocx/cpl etc)
; Returns: TRUE or FALSE. If TRUE a PE handle (hPE) is stored in the variable
; pointed to by lpdwPEHandle. If FALSE, use PE_GetError to get further info.
;
; Note: Calls PE_Analyze to process the PE file. Use PE_CloseFile when finished
;------------------------------------------------------------------------------
PE_OpenFile PROC USES EBX lpszPEFilename:DWORD, bReadOnly:DWORD, lpdwPEHandle:DWORD
    LOCAL hPE:DWORD
    LOCAL hPEFile:DWORD
    LOCAL PEMemMapHandle:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL PEFilesize:DWORD
    LOCAL PEVersion:DWORD
    
    IFDEF DEBUG32
    PrintText 'PE_OpenFile'
    ENDIF
    
    .IF lpdwPEHandle == NULL
        Invoke PE_SetError, NULL, PE_ERROR_NO_HANDLE
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszPEFilename == NULL
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_FILE
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF

    ;--------------------------------------------------------------------------
    ; Open file for read only or read/write access
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke CreateFile, lpszPEFilename, GENERIC_READ, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    .ELSE
        Invoke CreateFile, lpszPEFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL
    .ENDIF
    .IF eax == INVALID_HANDLE_VALUE
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_FILE
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov hPEFile, eax ; store file handle
    
    ;--------------------------------------------------------------------------
    ; Get file size and verify its not too low or too high in size
    ;--------------------------------------------------------------------------
    Invoke GetFileSize, hPEFile, NULL
    .IF eax < 268d ; https://www.bigmessowires.com/2015/10/08/a-handmade-executable-file/
        ; http://archive.is/w01DO#selection-265.0-265.44
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_SIZE_LOW
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ELSEIF eax > 1FFFFFFFh ; 536,870,911 536MB+ - rare to be this size or larger
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_SIZE_HIGH
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret    
    .ENDIF
    mov PEFilesize, eax ; file size

    ;--------------------------------------------------------------------------
    ; Create file mapping of entire file
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READONLY, 0, 0, NULL ; Create memory mapped file
    .ELSE
        Invoke CreateFileMapping, hPEFile, NULL, PAGE_READWRITE, 0, 0, NULL ; Create memory mapped file
    .ENDIF
    .IF eax == NULL
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_MAP
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov PEMemMapHandle, eax ; store mapping handle
    
    ;--------------------------------------------------------------------------
    ; Create view of file
    ;--------------------------------------------------------------------------
    .IF bReadOnly == TRUE
        Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_READ, 0, 0, 0, NULL
    .ELSE
        Invoke MapViewOfFileEx, PEMemMapHandle, FILE_MAP_ALL_ACCESS, 0, 0, 0, NULL
    .ENDIF    
    .IF eax == NULL
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_VIEW
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov PEMemMapPtr, eax ; store map view pointer

    ;--------------------------------------------------------------------------
    ; Check PE file signature - to make sure MZ and PE sigs are located
    ;--------------------------------------------------------------------------
    Invoke PESignature, PEMemMapPtr
    .IF eax == PE_INVALID
        ;----------------------------------------------------------------------
        ; Invalid PE file, so close all handles and return error
        ;----------------------------------------------------------------------
        Invoke UnmapViewOfFile, PEMemMapPtr
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_INVALID
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ELSE ; eax == PE_ARCH_32 || eax == PE_ARCH_64
        ;----------------------------------------------------------------------
        ; PE file is valid. So we process PE file and get pointers and other 
        ; information and store in a 'handle' (hPE) that we return. 
        ; Handle is a pointer to a PEINFO struct that stores PE file info.
        ;----------------------------------------------------------------------
        Invoke PE_Analyze, PEMemMapPtr, lpdwPEHandle
        .IF eax == FALSE
            ;------------------------------------------------------------------
            ; Error processing PE file, so close all handles and return error
            ;------------------------------------------------------------------        
            Invoke UnmapViewOfFile, PEMemMapPtr
            Invoke CloseHandle, PEMemMapHandle
            Invoke CloseHandle, hPEFile
            xor eax, eax
            ret
        .ENDIF
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Success in processing PE file. Store additional information like file and
    ; map handles and filesize in our PEINFO struct (hPE) if we reach here.
    ;--------------------------------------------------------------------------
    .IF lpdwPEHandle == NULL
        Invoke UnmapViewOfFile, PEMemMapPtr
        Invoke CloseHandle, PEMemMapHandle
        Invoke CloseHandle, hPEFile
        Invoke PE_SetError, NULL, PE_ERROR_OPEN_INVALID    
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF       
    
    mov ebx, lpdwPEHandle
    mov eax, [ebx]
    mov hPE, eax
    mov ebx, hPE
    mov eax, lpdwPEHandle
    mov [ebx].PEINFO.PEHandle, eax
    mov eax, bReadOnly
    mov [ebx].PEINFO.PEOpenMode, eax        
    mov eax, PEMemMapHandle
    mov [ebx].PEINFO.PEMemMapHandle, eax
    mov eax, hPEFile
    mov [ebx].PEINFO.PEFileHandle, eax
    mov eax, PEFilesize
    mov [ebx].PEINFO.PEFilesize, eax
    .IF lpszPEFilename != NULL
        lea eax, [ebx].PEINFO.PEFilename
        Invoke lstrcpyn, eax, lpszPEFilename, MAX_PATH
    .ENDIF        
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    mov ebx, lpdwPEHandle
    mov eax, hPE
    mov [ebx], eax
    
    ;mov eax, hPE ; Return handle for our user to store and use in other functions
    mov eax, TRUE
    ret
PE_OpenFile ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_CloseFile - Close PE File
; Returns: None
;------------------------------------------------------------------------------
PE_CloseFile PROC USES EBX hPE:DWORD

    IFDEF DEBUG32
    PrintText 'PE_CloseFile'
    ENDIF
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    mov ebx, hPE
    mov ebx, [ebx].PEINFO.PEHandle
    .IF ebx != 0
        mov eax, 0 ; null out hPE handle if it exists
        mov [ebx], eax
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    .IF eax != NULL
        Invoke UnmapViewOfFile, eax
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapHandle
    .IF eax != NULL
        Invoke CloseHandle, eax
    .ENDIF

    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEFileHandle
    .IF eax != NULL
        Invoke CloseHandle, eax
    .ENDIF

    mov eax, hPE
    .IF eax != NULL
        Invoke GlobalFree, eax
    .ENDIF
    
    Invoke PE_SetError, NULL, PE_ERROR_SUCCESS
    
    xor eax, eax
    ret
PE_CloseFile ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_Analyze - Process memory mapped PE file 
; Returns: TRUE or FALSE. If TRUE a PE handle (hPE) is stored in the variable
; pointed to by lpdwPEHandle. If FALSE, use PE_GetError to get further info.
;
; Can be used directly on memory region where PE is already loaded/mapped
;
; PE_Analyze is also called by PE_OpenFile.
; Note: Use PE_Finish when finished with PE file if using PE_Analyze directly.
;------------------------------------------------------------------------------
PE_Analyze PROC USES EBX EDX pPEInMemory:DWORD, lpdwPEHandle:DWORD
    LOCAL hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pFileHeader:DWORD
    LOCAL pOptionalHeader:DWORD
    LOCAL pDataDirectories:DWORD
    LOCAL pSectionTable:DWORD
    LOCAL pImportDirectoryTable:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwNumberOfSections:DWORD
    LOCAL dwSizeOfOptionalHeader:DWORD
    LOCAL dwNumberOfRvaAndSizes:DWORD
    LOCAL dwCurrentSection:DWORD
    LOCAL bPE64:DWORD
    LOCAL dwRVA:DWORD
    LOCAL dwOffset:DWORD
    
    IFDEF DEBUG32
    PrintText 'PE_Analyze'
    ENDIF    
    
    .IF lpdwPEHandle == NULL
        Invoke PE_SetError, NULL, PE_ERROR_NO_HANDLE
        xor eax, eax
        ret
    .ENDIF    
    
    .IF pPEInMemory == NULL
        Invoke PE_SetError, NULL, PE_ERROR_ANALYZE_NULL
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    
    mov eax, pPEInMemory
    mov PEMemMapPtr, eax       
    
    ;--------------------------------------------------------------------------
    ; Alloc mem for our PE Handle (PEINFO)
    ;--------------------------------------------------------------------------
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, SIZEOF PEINFO
    .IF eax == NULL
        Invoke PE_SetError, NULL, PE_ERROR_ANALYZE_ALLOC
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF
    mov hPE, eax
    
    mov edx, hPE
    mov eax, PEMemMapPtr
    mov [edx].PEINFO.PEMemMapPtr, eax
    mov [edx].PEINFO.PEDOSHeader, eax

    ; Process PE in memory
    mov eax, PEMemMapPtr
    mov ebx, eax ; ebx points to IMAGE_DOS_HEADER in memory
    .IF [ebx].IMAGE_DOS_HEADER.e_lfanew == 0
        Invoke PE_SetError, hPE, PE_ERROR_ANALYZE_INVALID
        .IF hPE != NULL
            Invoke GlobalFree, hPE
        .ENDIF
        mov ebx, lpdwPEHandle
        mov eax, 0
        mov [ebx], eax
        xor eax, eax
        ret
    .ENDIF    
    
    ;--------------------------------------------------------------------------
    ; Get headers: NT, File, Optional & other useful fields
    ;--------------------------------------------------------------------------
    ; ebx points to IMAGE_DOS_HEADER in memory
    add eax, [ebx].IMAGE_DOS_HEADER.e_lfanew
    mov [edx].PEINFO.PENTHeader, eax
    mov ebx, eax ; ebx points to IMAGE_NT_HEADERS
    lea eax, [ebx].IMAGE_NT_HEADERS.FileHeader
    mov [edx].PEINFO.PEFileHeader, eax
    mov pFileHeader, eax
    lea eax, [ebx].IMAGE_NT_HEADERS.OptionalHeader
    mov [edx].PEINFO.PEOptionalHeader, eax
    mov pOptionalHeader, eax
    mov ebx, pFileHeader ; ebx points to IMAGE_FILE_HEADER
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.NumberOfSections
    mov [edx].PEINFO.PESectionCount, eax
    mov dwNumberOfSections, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.SizeOfOptionalHeader
    mov [edx].PEINFO.PEOptionalHeaderSize, eax
    mov dwSizeOfOptionalHeader, eax
    movzx eax, word ptr [ebx].IMAGE_FILE_HEADER.Characteristics
    and eax, IMAGE_FILE_DLL
    .IF eax == IMAGE_FILE_DLL
        mov [edx].PEINFO.PEDLL, TRUE
    .ELSE
        mov [edx].PEINFO.PEDLL, FALSE
    .ENDIF        
    
    .IF dwSizeOfOptionalHeader == 0
        mov pOptionalHeader, 0
        mov pDataDirectories, 0
        mov dwNumberOfRvaAndSizes, 0
        mov bPE64, FALSE
    .ELSE
        ;----------------------------------------------------------------------
        ; Get PE32/PE32+ magic number
        ;----------------------------------------------------------------------
        mov ebx, pOptionalHeader; ebx points to IMAGE_OPTIONAL_HEADER
        movzx eax, word ptr [ebx]
        .IF eax == IMAGE_NT_OPTIONAL_HDR32_MAGIC ; PE32
            mov ebx, hPE
            mov [edx].PEINFO.PE64, FALSE
            mov bPE64, FALSE
        .ELSEIF eax == IMAGE_NT_OPTIONAL_HDR64_MAGIC ; PE32+ (PE64)
            mov ebx, hPE
            mov [edx].PEINFO.PE64, TRUE
            mov bPE64, TRUE
        .ELSE ; ROM or something else
            Invoke PE_SetError, hPE, PE_ERROR_ANALYZE_INVALID
            .IF hPE != NULL
                Invoke GlobalFree, hPE
            .ENDIF
            mov ebx, lpdwPEHandle
            mov eax, 0
            mov [ebx], eax
            xor eax, eax
            ret
        .ENDIF
        
        mov eax, dwSizeOfOptionalHeader
        .IF eax == 28 || eax == 24
            ;------------------------------------------------------------------
            ; Standard fields in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            mov pDataDirectories, 0
            mov dwNumberOfRvaAndSizes, 0
        .ELSEIF eax == 68 || eax == 88 ; Windows specific fields in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            ; Windows specific fields in IMAGE_OPTIONAL_HEADER
            ; Get ImageBase, Subsystem, DllCharacteristics
            ;------------------------------------------------------------------
            mov pDataDirectories, 0
            mov dwNumberOfRvaAndSizes, 0
            mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
            .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx].PEINFO.PE64ImageBase, eax
                mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx+4].PEINFO.PE64ImageBase, eax 
                mov [edx].PEINFO.PEImageBase, 0
             .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                mov [edx].PEINFO.PEImageBase, eax
            .ENDIF
        .ELSE
            ;------------------------------------------------------------------
            ; Data Directories in IMAGE_OPTIONAL_HEADER
            ;------------------------------------------------------------------
            mov ebx, pOptionalHeader ; ebx points to IMAGE_OPTIONAL_HEADER
            .IF bPE64 == TRUE ; ebx points to IMAGE_OPTIONAL_HEADER64
                mov eax, dword ptr [ebx].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx].PEINFO.PE64ImageBase, eax
                mov eax, dword ptr [ebx+4].IMAGE_OPTIONAL_HEADER64.ImageBase
                mov dword ptr [edx+4].PEINFO.PE64ImageBase, eax 
                mov [edx].PEINFO.PEImageBase, 0
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER64.NumberOfRvaAndSizes
                mov [edx].PEINFO.PENumberOfRvaAndSizes, eax
                mov dwNumberOfRvaAndSizes, eax
                mov ebx, pOptionalHeader
                add ebx, SIZEOF_STANDARD_FIELDS_PE64
                add ebx, SIZEOF_WINDOWS_FIELDS_PE64                    
                mov pDataDirectories, ebx
            .ELSE ; ebx points to IMAGE_OPTIONAL_HEADER32
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.ImageBase
                mov [edx].PEINFO.PEImageBase, eax
                mov eax, [ebx].IMAGE_OPTIONAL_HEADER32.NumberOfRvaAndSizes
                mov [edx].PEINFO.PENumberOfRvaAndSizes, eax
                mov dwNumberOfRvaAndSizes, eax
                mov ebx, pOptionalHeader
                add ebx, SIZEOF_STANDARD_FIELDS_PE32
                add ebx, SIZEOF_WINDOWS_FIELDS_PE32
                mov pDataDirectories, ebx
            .ENDIF                
        .ENDIF
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Get pointer to SectionTable
    ;--------------------------------------------------------------------------
    mov eax, pFileHeader
    add eax, SIZEOF IMAGE_FILE_HEADER
    add eax, dwSizeOfOptionalHeader
    mov [edx].PEINFO.PESectionTable, eax
    mov pSectionTable, eax
    mov pCurrentSection, eax
    
    mov dwCurrentSection, 0
    mov eax, 0
    .WHILE eax < dwNumberOfSections
        mov ebx, pCurrentSection
        ; do stuff with sections
        ; PointerToRawData to get section data
        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        inc dwCurrentSection
        mov eax, dwCurrentSection
    .ENDW
    
    ;--------------------------------------------------------------------------
    ; Get Data Directories
    ;--------------------------------------------------------------------------
    IFDEF DEBUG32
    mov eax, dwNumberOfRvaAndSizes
    mov ebx, SIZEOF IMAGE_DATA_DIRECTORY
    mul ebx
    DbgDump pDataDirectories, eax
    ENDIF
    
    mov pImportDirectoryTable, 0
    
    .IF pDataDirectories != 0
        mov edx, hPE
        .IF dwNumberOfRvaAndSizes > 0 ; Export Table
            mov ebx, pDataDirectories
            mov eax, [ebx].IMAGE_DATA_DIRECTORY.VirtualAddress
            .IF eax != 0
                Invoke PE_RVAToOffset, hPE, eax
                add eax, PEMemMapPtr
                mov [edx].PEINFO.PEExportDirectoryTable, eax
            .ENDIF
        .ENDIF
    .ENDIF

    IFDEF DEBUG32
    mov eax, dwNumberOfSections
    mov ebx, SIZEOF IMAGE_SECTION_HEADER
    mul ebx
    DbgDump pSectionTable, eax    
    ENDIF

    ;--------------------------------------------------------------------------
    ; Update PEINFO handle information
    ;--------------------------------------------------------------------------
    mov edx, hPE
    mov eax, lpdwPEHandle
    mov [edx].PEINFO.PEHandle, eax

    mov ebx, lpdwPEHandle
    mov eax, hPE
    mov [ebx], eax

    mov eax, TRUE
    ret
PE_Analyze ENDP



;##############################################################################
;  E X P O R T   S E C T I O N   F U N C T I O N S
;##############################################################################

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportDirectoryTable - Get pointer to ExportDirectoryTable
; Returns: pointer to ExportDirectoryTable or NULL
;------------------------------------------------------------------------------
PE_ExportDirectoryTable PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEExportDirectoryTable
    ret
PE_ExportDirectoryTable ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportNamePointerTable
;------------------------------------------------------------------------------
PE_ExportNamePointerTable PROC USES EBX hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL pExportDirectoryTable:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax ; ebx is pExportDirectoryTable
    
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.AddressOfNames
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr
    ; eax has pointer to Export Name Pointer Table RVA
    ret
PE_ExportNamePointerTable ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportNameCount - Get count of names in the ExportDirectoryTable
; Returns: count of names or 0
;------------------------------------------------------------------------------
PE_ExportNameCount PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.NumberOfNames
    ret
PE_ExportNameCount ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportDLLName - Get DLL name for exports 
; Returns: address of zero terminated DLL name string, or NULL
;------------------------------------------------------------------------------
PE_ExportDLLName PROC USES EBX hPE:DWORD
    LOCAL PEMemMapPtr:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax

    Invoke PE_ExportDirectoryTable, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov ebx, eax ; ebx is pExportDirectoryTable
    
    mov eax, [ebx].IMAGE_EXPORT_DIRECTORY.nName
    Invoke PE_RVAToOffset, hPE, eax
    add eax, PEMemMapPtr
    ; eax has pointer to DLL name
    ret
PE_ExportDLLName ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportFunctionNames - Get function names exported in the DLL
; Returns: count of functions in lpdwFunctionsList array or 0.
; On succesful return lpdwFunctionsList points to a DWORD array containing
; pointers to the function names. Use GlobalFree on this array once finished.
;------------------------------------------------------------------------------
PE_ExportFunctionNames PROC USES EBX hPE:DWORD, lpdwFunctionsList:DWORD
    LOCAL PEMemMapPtr:DWORD
    LOCAL dwExportCount:DWORD
    LOCAL pExportNamePointerTable:DWORD
    LOCAL pExportNamePointerTableEntry:DWORD
    LOCAL dwHintNameTableRVA:DWORD
    LOCAL pNameList:DWORD
    LOCAL pNameListNextFunction:DWORD
    LOCAL dwNameListSize:DWORD
    LOCAL nExport:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpdwFunctionsList == 0
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEMemMapPtr
    mov PEMemMapPtr, eax
    
    Invoke PE_ExportNameCount, hPE
    .IF eax == NULL
        ret
    .ENDIF
    mov dwExportCount, eax
    
    Invoke PE_ExportNamePointerTable, hPE
    .IF eax == NULL
        ret
    .ENDIF
    mov pExportNamePointerTable, eax
    mov pExportNamePointerTableEntry, eax
    
    ; calc max name list string size
    mov eax, dwExportCount
    inc eax
    mov ebx, SIZEOF DWORD
    mul ebx
    mov dwNameListSize, eax
    
    Invoke GlobalAlloc, GMEM_FIXED or GMEM_ZEROINIT, dwNameListSize
    .IF eax == NULL
        ret
    .ENDIF
    mov pNameList, eax
    mov pNameListNextFunction, eax

    mov ebx, pExportNamePointerTableEntry
    mov nExport, 0
    mov eax, 0
    .WHILE eax < dwExportCount
        mov eax, [ebx] ; get rva pointer to function string 
        Invoke PE_RVAToOffset, hPE, eax
        .IF eax == 0
            ret
        .ENDIF    
        add eax, PEMemMapPtr ; eax is pointer to function string
        mov ebx, pNameListNextFunction
        mov [ebx], eax ; store pointer to function string in our array

        add pNameListNextFunction, SIZEOF DWORD
        add pExportNamePointerTableEntry, SIZEOF DWORD ; pointers are always 32bits

        mov ebx, pExportNamePointerTableEntry
        inc nExport
        mov eax, nExport
    .ENDW
    
    mov ebx, lpdwFunctionsList
    mov eax, pNameList
    mov [ebx], eax
    
    mov eax, dwExportCount
    ret
PE_ExportFunctionNames ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_ExportFunctionNameToDef - Creates a .DEF file from export functions 
;------------------------------------------------------------------------------
PE_ExportFunctionNameToDef PROC USES EBX hPE:DWORD, lpszDefFilename:DWORD, bUseFilename:DWORD, bRemoveUnderscore:DWORD
    LOCAL pExportFunctionNamesList:DWORD
    LOCAL pExportName:DWORD
    LOCAL nExportName:DWORD
    LOCAL dwExportNameCount:DWORD
    LOCAL lpszExportName:DWORD
    LOCAL lpszExportDllName:DWORD
    LOCAL hDefFile:DWORD
    LOCAL dwNumberOfBytesToWrite:DWORD
    LOCAL dwNumberOfBytesWritten:DWORD
    LOCAL szDefFilename[MAX_PATH]:BYTE
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    .IF lpszDefFilename == NULL
        ; create def file based on export name (usually a .dll) 
        lea ebx, szDefFilename
        mov byte ptr [ebx], '.'
        mov byte ptr [ebx+1], '\'
        .IF bUseFilename == TRUE
            Invoke PE_FileNameOnly, hPE, Addr szDefFilename+2
            Invoke lstrcat, Addr szDefFilename, CTEXT(".def")
        .ELSE
            Invoke PE_ExportDLLName, hPE
            Invoke lstrcpyn, Addr szDefFilename+2, eax, MAX_PATH
            Invoke lstrlen, Addr szDefFilename
            lea ebx, szDefFilename
            add ebx, eax
            sub ebx, 4
            mov eax, [ebx]
            .IF eax == 'LLD.' || eax == 'lld.' || eax == 'EXE.' || eax == 'exe.'
                mov byte ptr [ebx+1], 'd'
                mov byte ptr [ebx+2], 'e'
                mov byte ptr [ebx+3], 'f'
                mov byte ptr [ebx+4], 0
            .ELSE
                xor eax, eax
                ret
            .ENDIF
        .ENDIF
    .ENDIF
    
    Invoke PE_ExportNameCount, hPE
    .IF eax == 0
        ret
    .ENDIF
    mov dwExportNameCount, eax
    
    Invoke PE_ExportFunctionNames, hPE, Addr pExportFunctionNamesList
    .IF eax == 0
        ret
    .ENDIF
    
    mov eax, pExportFunctionNamesList
    mov pExportName, eax
    
    ; Create DEF file
    .IF lpszDefFilename == NULL
        Invoke CreateFile, Addr szDefFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    .ELSE
        Invoke CreateFile, lpszDefFilename, GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    .ENDIF
    .IF eax == INVALID_HANDLE_VALUE
        xor eax, eax
        ret
    .ENDIF
    mov hDefFile, eax
    
    ; Write out LIBRARY and EXPORTS to DEF file
    Invoke WriteFile, hDefFile, Addr DEFLIBRARY, dwLenDEFLIBRARY, Addr dwNumberOfBytesWritten, NULL

    .IF bUseFilename == TRUE
        Invoke PE_FileNameOnly, hPE, Addr szDefFilename ; reuse szDefFilename buffer
        Invoke lstrlen, Addr szDefFilename
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, Addr szDefFilename, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
    .ELSE
        Invoke PE_ExportDLLName, hPE
        mov lpszExportDllName, eax
        Invoke lstrlen, lpszExportDllName
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, lpszExportDllName, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
    .ENDIF
    Invoke WriteFile, hDefFile, Addr DEFCRLF, dwLenDEFCRLF, Addr dwNumberOfBytesWritten, NULL
    Invoke WriteFile, hDefFile, Addr DEFEXPORTS, dwLenDEFEXPORTS, Addr dwNumberOfBytesWritten, NULL
    
    mov nExportName, 0
    mov eax, 0
    .WHILE eax < dwExportNameCount
        mov ebx, pExportName
        mov eax, [ebx]
        mov lpszExportName, eax
        
        .IF bRemoveUnderscore == TRUE
            mov ebx, lpszExportName
            movzx eax, byte ptr [ebx]
            .IF al == '_'
                inc lpszExportName
            .ENDIF
        .ENDIF
        
        ; Write out function name to DEF file
        Invoke WriteFile, hDefFile, Addr DEFINDENT, dwLenDEFINDENT, Addr dwNumberOfBytesWritten, NULL
        Invoke lstrlen, lpszExportName
        mov dwNumberOfBytesToWrite, eax
        Invoke WriteFile, hDefFile, lpszExportName, dwNumberOfBytesToWrite, Addr dwNumberOfBytesWritten, NULL
        Invoke WriteFile, hDefFile, Addr DEFCRLF, dwLenDEFCRLF, Addr dwNumberOfBytesWritten, NULL
        
        add pExportName, SIZEOF DWORD
        inc nExportName
        mov eax, nExportName
    .ENDW
    
    ; Close DEF File
    Invoke CloseHandle, hDefFile

    mov eax, TRUE
    ret
PE_ExportFunctionNameToDef ENDP



;##############################################################################
;  I N F O   F U N C T I O N S
;##############################################################################

PE_ALIGN
;------------------------------------------------------------------------------
; PE_DLL - returns TRUE if DLL or FALSE otherwise
;------------------------------------------------------------------------------
PE_DLL PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PEDLL
    ret
PE_DLL ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; PE_PE64 - returns TRUE if PE32+ (PE64) or FALSE if PE32
;------------------------------------------------------------------------------
PE_PE64 PROC USES EBX hPE:DWORD
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PE64
    ret
PE_PE64 ENDP


;##############################################################################
;  E R R O R   F U N C T I O N S
;##############################################################################

PE_ALIGN
;------------------------------------------------------------------------------
; PE_SetError
;------------------------------------------------------------------------------
PE_SetError PROC USES EBX hPE:DWORD, dwError:DWORD
    .IF hPE != NULL && dwError != PE_ERROR_SUCCESS
        mov ebx, hPE
        mov ebx, [ebx].PEINFO.PEHandle 
        .IF ebx != 0
            mov eax, 0 ; null out hPE handle if it exists
            mov [ebx], eax
        .ENDIF
    .ENDIF
    mov eax, dwError
    mov PELIB_ErrorNo, eax
    ret
PE_SetError ENDP


;##############################################################################
;  H E L P E R   F U N C T I O N S
;##############################################################################

PE_ALIGN
;------------------------------------------------------------------------------
; PE_RVAToOffset - convert Relative Virtual Address (RVA) to file offset
;------------------------------------------------------------------------------
PE_RVAToOffset PROC USES EBX EDX hPE:DWORD, dwRVA:DWORD
    LOCAL nTotalSections:DWORD
    LOCAL nCurrentSection:DWORD
    LOCAL pCurrentSection:DWORD
    LOCAL dwSectionSize:DWORD
    LOCAL dwVirtualAddress:DWORD
    LOCAL dwPointerToRawData:DWORD
    
    .IF hPE == NULL
        xor eax, eax
        ret
    .ENDIF
    
    mov ebx, hPE
    mov eax, [ebx].PEINFO.PESectionCount
    mov nTotalSections, eax
    mov eax, [ebx].PEINFO.PESectionTable
    mov pCurrentSection, eax

    mov ebx, pCurrentSection
    mov edx, dwRVA
    mov eax, 0
    mov nCurrentSection, 0
    .WHILE eax < nTotalSections
        mov eax, [ebx].IMAGE_SECTION_HEADER.Misc.VirtualSize
        .IF eax == 0
            mov eax, [ebx].IMAGE_SECTION_HEADER.SizeOfRawData
        .ENDIF
        mov dwSectionSize, eax
    
        mov eax, [ebx].IMAGE_SECTION_HEADER.VirtualAddress
        .IF eax <= edx
            mov dwVirtualAddress, eax
            add eax, dwSectionSize
            .IF eax > edx
                mov eax, [ebx].IMAGE_SECTION_HEADER.PointerToRawData
                mov dwPointerToRawData, eax
                
                mov ebx, dwVirtualAddress
                mov eax, edx
                sub eax, ebx
                mov edx, eax
                mov ebx, dwPointerToRawData
                mov eax, edx
                add eax, ebx
                ret
            .ENDIF
        .ENDIF

        add pCurrentSection, SIZEOF IMAGE_SECTION_HEADER
        mov ebx, pCurrentSection
        inc nCurrentSection
        mov eax, nCurrentSection
    .ENDW
    
    mov eax, dwRVA
    ret
PE_RVAToOffset ENDP



PE_ALIGN
;------------------------------------------------------------------------------
; PE_FileName - returns in eax pointer to zero terminated string contained filename that is open or NULL if not opened
;------------------------------------------------------------------------------
PE_FileName PROC USES EBX hPE:DWORD
    LOCAL PEFilename:DWORD
    .IF hPE == NULL
        mov eax, NULL
        ret
    .ENDIF
    mov ebx, hPE
    lea eax, [ebx].PEINFO.PEFilename
    mov PEFilename, eax
    Invoke lstrlen, PEFilename
    .IF eax == 0
        mov eax, NULL
    .ELSE
        mov eax, PEFilename
    .ENDIF
    ret
PE_FileName endp

PE_ALIGN
;------------------------------------------------------------------------------
; PE_FileNameOnly - returns in eax true or false if it managed to pass to the buffer pointed at lpszFileNameOnly, the stripped filename without extension
;------------------------------------------------------------------------------
PE_FileNameOnly PROC hPE:DWORD, lpszFileNameOnly:DWORD
    Invoke PE_FileName, hPE
    .IF eax == NULL
        mov eax, FALSE
        ret
    .ENDIF
    Invoke PEJustFname, eax, lpszFileNameOnly
    mov eax, TRUE
    ret
PE_FileNameOnly endp




;##############################################################################
;  I N T E R N A L   F U N C T I O N S
;##############################################################################

PE_ALIGN
;------------------------------------------------------------------------------
; Checks the PE signatures to determine if they are valid
;------------------------------------------------------------------------------
PESignature PROC USES EBX pPEInMemory:DWORD
    mov ebx, pPEInMemory
    movzx eax, word ptr [ebx].IMAGE_DOS_HEADER.e_magic
    .IF ax == MZ_SIGNATURE
        add ebx, [ebx].IMAGE_DOS_HEADER.e_lfanew
        ; ebx is pointer to IMAGE_NT_HEADERS now
        mov eax, [ebx].IMAGE_NT_HEADERS.Signature
        .IF ax == PE_SIGNATURE
            movzx eax, word ptr [ebx].IMAGE_NT_HEADERS.OptionalHeader.Magic
            .IF ax == IMAGE_NT_OPTIONAL_HDR32_MAGIC
                mov eax, PE_ARCH_32
                ret
            .ELSEIF ax == IMAGE_NT_OPTIONAL_HDR64_MAGIC
                mov eax, PE_ARCH_64
                ret
            .ENDIF
        .ENDIF
    .ENDIF
    mov eax, PE_INVALID
    ret
PESignature ENDP

PE_ALIGN
;------------------------------------------------------------------------------
; Strip path name to just filename Without extention
;------------------------------------------------------------------------------
PEJustFname PROC szFilePathName:DWORD, szFileName:DWORD
    LOCAL LenFilePathName:DWORD
    LOCAL nPosition:DWORD
    
    Invoke lstrlen, szFilePathName
    mov LenFilePathName, eax
    mov nPosition, eax
    
    .IF LenFilePathName == 0
        mov byte ptr [edi], 0
        ret
    .ENDIF
    
    mov esi, szFilePathName
    add esi, eax
    
    mov eax, nPosition
    .WHILE eax != 0
        movzx eax, byte ptr [esi]
        .IF al == '\' || al == ':' || al == '/'
            inc esi
            .BREAK
        .ENDIF
        dec esi
        dec nPosition
        mov eax, nPosition
    .ENDW
    mov edi, szFileName
    mov eax, nPosition
    .WHILE eax != LenFilePathName
        movzx eax, byte ptr [esi]
        .IF al == '.' ; stop here
            .BREAK
        .ENDIF
        mov byte ptr [edi], al
        inc edi
        inc esi
        inc nPosition
        mov eax, nPosition
    .ENDW
    mov byte ptr [edi], 0h
    ret
PEJustFname ENDP

;------------------------------------------------------------------------------
; PEDwordToAscii - Paul Dixon's utoa_ex function. unsigned dword to ascii.
; Returns: Buffer pointed to by lpszAsciiString will contain ascii string
;------------------------------------------------------------------------------
OPTION PROLOGUE:NONE
OPTION EPILOGUE:NONE
PEDwordToAscii PROC dwValue:DWORD, lpszAsciiString:DWORD
    mov eax, [esp+4]                ; uvar      : unsigned variable to convert
    mov ecx, [esp+8]                ; pbuffer   : pointer to result buffer

    push esi
    push edi

    jmp udword

  align 4
  chartab:
    dd "00","10","20","30","40","50","60","70","80","90"
    dd "01","11","21","31","41","51","61","71","81","91"
    dd "02","12","22","32","42","52","62","72","82","92"
    dd "03","13","23","33","43","53","63","73","83","93"
    dd "04","14","24","34","44","54","64","74","84","94"
    dd "05","15","25","35","45","55","65","75","85","95"
    dd "06","16","26","36","46","56","66","76","86","96"
    dd "07","17","27","37","47","57","67","77","87","97"
    dd "08","18","28","38","48","58","68","78","88","98"
    dd "09","19","29","39","49","59","69","79","89","99"

  udword:
    mov esi, ecx                    ; get pointer to answer
    mov edi, eax                    ; save a copy of the number

    mov edx, 0D1B71759h             ; =2^45\10000    13 bit extra shift
    mul edx                         ; gives 6 high digits in edx

    mov eax, 68DB9h                 ; =2^32\10000+1

    shr edx, 13                     ; correct for multiplier offset used to give better accuracy
    jz short skiphighdigits         ; if zero then don't need to process the top 6 digits

    mov ecx, edx                    ; get a copy of high digits
    imul ecx, 10000                 ; scale up high digits
    sub edi, ecx                    ; subtract high digits from original. EDI now = lower 4 digits

    mul edx                         ; get first 2 digits in edx
    mov ecx, 100                    ; load ready for later

    jnc short next1                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZeroSupressed              ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    inc esi                         ; update pointer by 1
    jmp  ZS1                        ; continue with pairs of digits to the end

  align 16
  next1:
    mul ecx                         ; get next 2 digits
    jnc short next2                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZS1a                       ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    add esi, 1                      ; update pointer by 1
    jmp  ZS2                        ; continue with pairs of digits to the end

  align 16
  next2:
    mul ecx                         ; get next 2 digits
    jnc short next3                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja   ZS2a                       ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    add esi, 1                      ; update pointer by 1
    jmp  ZS3                        ; continue with pairs of digits to the end

  align 16
  next3:

  skiphighdigits:
    mov eax, edi                    ; get lower 4 digits
    mov ecx, 100

    mov edx, 28F5C29h               ; 2^32\100 +1
    mul edx
    jnc short next4                 ; if zero, supress them by ignoring
    cmp edx, 9                      ; 1 digit or 2?
    ja  short ZS3a                  ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    inc esi                         ; update pointer by 1
    jmp short  ZS4                  ; continue with pairs of digits to the end

  align 16
  next4:
    mul ecx                         ; this is the last pair so don; t supress a single zero
    cmp edx, 9                      ; 1 digit or 2?
    ja  short ZS4a                  ; 2 digits, just continue with pairs of digits to the end

    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dh                   ; but only write the 1 we need, supress the leading zero
    mov byte ptr [esi+1], 0         ; zero terminate string

    pop edi
    pop esi
    ret 8

  align 16
  ZeroSupressed:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx
    add esi, 2                      ; write them to answer

  ZS1:
    mul ecx                         ; get next 2 digits
  ZS1a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write them to answer
    add esi, 2

  ZS2:
    mul ecx                         ; get next 2 digits
  ZS2a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write them to answer
    add esi, 2

  ZS3:
    mov eax, edi                    ; get lower 4 digits
    mov edx, 28F5C29h               ; 2^32\100 +1
    mul edx                         ; edx= top pair
  ZS3a:
    mov edx, chartab[edx*4]         ; look up 2 digits
    mov [esi], dx                   ; write to answer
    add esi, 2                      ; update pointer

  ZS4:
    mul ecx                         ; get final 2 digits
  ZS4a:
    mov edx, chartab[edx*4]         ; look them up
    mov [esi], dx                   ; write to answer

    mov byte ptr [esi+2], 0         ; zero terminate string

  sdwordend:

    pop edi
    pop esi
    ret 8
PEDwordToAscii ENDP
OPTION PROLOGUE:PrologueDef
OPTION EPILOGUE:EpilogueDef
























