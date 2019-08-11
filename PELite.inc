;==============================================================================
;
; PE LIBRARY - Special Lite Version For Dll2Def
;
;==============================================================================

;------------------------------------------------------------------------------
; PE Prototypes
;------------------------------------------------------------------------------
PE_OpenFile                 PROTO :DWORD,:DWORD,:DWORD              ; lpszPEFilename, bReadOnly, lpdwPEHandle. Returns in eax a handle used in other functions: hPE
PE_CloseFile                PROTO :DWORD                            ; hPE returned from PE_OpenFile.
PE_Analyze                  PROTO :DWORD,:DWORD                     ; pPEInMemory, lpdwPEHandle. Returns in eax a handle used in other functions: hPE

; Export Functions
PE_ExportDirectoryTable     PROTO :DWORD                            ; hPE
PE_ExportNamePointerTable   PROTO :DWORD                            ; hPE
PE_ExportNameCount          PROTO :DWORD                            ; hPE
PE_ExportDLLName            PROTO :DWORD                            ; hPE
PE_ExportFunctionNames      PROTO :DWORD,:DWORD                     ; hPE, lpdwFunctionsList
PE_ExportFunctionNameToDef  PROTO :DWORD,:DWORD,:DWORD,:DWORD       ; hPE, lpszDefFilename, bUseFilename, bRemoveUnderscore

PE_DLL                      PROTO :DWORD                            ; hPE
PE_PE64                     PROTO :DWORD                            ; hPE

; Helper Functions:
PE_RVAToOffset              PROTO :DWORD,:DWORD                     ; hPE, dwRVA
PE_FileName                 PROTO :DWORD                            ; hPE
PE_FileNameOnly             PROTO :DWORD,:DWORD                     ; hPE, lpszFileNameOnly



;------------------------------------------------------------------------------
; Structures for internal use
;------------------------------------------------------------------------------
IFNDEF PEINFO
PEINFO                      STRUCT
    PEOpenMode              DD 0
    PEHandle                DD 0
    PEFilename              DB MAX_PATH DUP (0)
    PEFilesize              DD 0
    PEVersion               DD 0
    PE64                    DD 0
    PEDLL                   DD 0
    PEDOSHeader             DD 0
    PENTHeader              DD 0
    PEFileHeader            DD 0
    PEOptionalHeader        DD 0
    PESectionTable          DD 0
    PESectionCount          DD 0
    PEOptionalHeaderSize    DD 0
    PEImageBase             DD 0
    PE64ImageBase           DQ 0
    PENumberOfRvaAndSizes   DD 0
    PEDataDirectories       DD 0
    PEExportCount           DD 0
    PEExportDirectoryTable  DD 0
    PEExportAddressTable    DD 0
    PEExportNamePointerTable DD 0
    PEExportOrdinalTable    DD 0
    PEExportNameTable       DD 0
    PEMemMapPtr             DD 0
    PEMemMapHandle          DD 0
    PEFileHandle            DD 0
PEINFO                      ENDS
ENDIF


;------------------------------------------------------------------------------
; PE Structures
;------------------------------------------------------------------------------
IFNDEF IMAGE_DATA_DIRECTORY
IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress   DWORD ?
    isize            DWORD ?
IMAGE_DATA_DIRECTORY ENDS
ENDIF

IFNDEF IMAGE_SECTION_HEADER
IMAGE_SECTION_HEADER     STRUCT
    Name1 DB IMAGE_SIZEOF_SHORT_NAME dup(?)
    union Misc
        PhysicalAddress  DWORD ?
        VirtualSize      DWORD ?
    ends
    VirtualAddress       DWORD ?
    SizeOfRawData        DWORD ?
    PointerToRawData     DWORD ?
    PointerToRelocations DWORD ?
    PointerToLinenumbers DWORD ?
    NumberOfRelocations  WORD  ?
    NumberOfLinenumbers  WORD  ?
    Characteristics      DWORD ?
IMAGE_SECTION_HEADER     ENDS
ENDIF

IFNDEF IMAGE_OPTIONAL_HEADER32
IMAGE_OPTIONAL_HEADER32         STRUCT
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    BaseOfData                  DWORD ?
    ImageBase                   DWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD  ?
    MinorOperatingSystemVersion WORD  ?
    MajorImageVersion           WORD  ?
    MinorImageVersion           WORD  ?
    MajorSubsystemVersion       WORD  ?
    MinorSubsystemVersion       WORD  ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD  ?
    DllCharacteristics          WORD  ?
    SizeOfStackReserve          DWORD ?
    SizeOfStackCommit           DWORD ?
    SizeOfHeapReserve           DWORD ?
    SizeOfHeapCommit            DWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)
IMAGE_OPTIONAL_HEADER32         ENDS
ENDIF

IFNDEF IMAGE_OPTIONAL_HEADER64
IMAGE_OPTIONAL_HEADER64         STRUCT
    Magic                       WORD  ?
    MajorLinkerVersion          BYTE  ?
    MinorLinkerVersion          BYTE  ?
    SizeOfCode                  DWORD ?
    SizeOfInitializedData       DWORD ?
    SizeOfUninitializedData     DWORD ?
    AddressOfEntryPoint         DWORD ?
    BaseOfCode                  DWORD ?
    ImageBase                   QWORD ?
    SectionAlignment            DWORD ?
    FileAlignment               DWORD ?
    MajorOperatingSystemVersion WORD  ?
    MinorOperatingSystemVersion WORD  ?
    MajorImageVersion           WORD  ?
    MinorImageVersion           WORD  ?
    MajorSubsystemVersion       WORD  ?
    MinorSubsystemVersion       WORD  ?
    Win32VersionValue           DWORD ?
    SizeOfImage                 DWORD ?
    SizeOfHeaders               DWORD ?
    CheckSum                    DWORD ?
    Subsystem                   WORD  ?
    DllCharacteristics          WORD  ?
    SizeOfStackReserve          QWORD ?
    SizeOfStackCommit           QWORD ?
    SizeOfHeapReserve           QWORD ?
    SizeOfHeapCommit            QWORD ?
    LoaderFlags                 DWORD ?
    NumberOfRvaAndSizes         DWORD ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES dup(<>)
IMAGE_OPTIONAL_HEADER64         ENDS
ENDIF

IMAGE_OPTIONAL_HEADER  equ  <IMAGE_OPTIONAL_HEADER32>

IFNDEF IMAGE_FILE_HEADER
IMAGE_FILE_HEADER        STRUCT
    Machine              WORD  ?
    NumberOfSections     WORD  ?
    TimeDateStamp        DWORD ?
    PointerToSymbolTable DWORD ?
    NumberOfSymbols      DWORD ?
    SizeOfOptionalHeader WORD  ?
    Characteristics      WORD  ?
IMAGE_FILE_HEADER        ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS
IMAGE_NT_HEADERS   STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS   ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS32
IMAGE_NT_HEADERS32 STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER32 <>
IMAGE_NT_HEADERS32 ENDS
ENDIF

IFNDEF IMAGE_NT_HEADERS64
IMAGE_NT_HEADERS64 STRUCT
    Signature      DWORD                   ?
    FileHeader     IMAGE_FILE_HEADER       <>
    OptionalHeader IMAGE_OPTIONAL_HEADER64 <>
IMAGE_NT_HEADERS64 ENDS
ENDIF

IFNDEF IMAGE_EXPORT_DIRECTORY
IMAGE_EXPORT_DIRECTORY    STRUCT
    Characteristics       DWORD ?
    TimeDateStamp         DWORD ?
    MajorVersion          WORD  ?
    MinorVersion          WORD  ?
    nName                 DWORD ?
    nBase                 DWORD ?
    NumberOfFunctions     DWORD ?
    NumberOfNames         DWORD ?
    AddressOfFunctions    DWORD ?
    AddressOfNames        DWORD ?
    AddressOfNameOrdinals DWORD ?
IMAGE_EXPORT_DIRECTORY    ENDS
ENDIF

IFNDEF IMAGE_DOS_HEADER
IMAGE_DOS_HEADER STRUCT
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
    e_res        WORD 4 dup(?)
    e_oemid      WORD ?
    e_oeminfo    WORD ?
    e_res2       WORD 10 dup(?)
    e_lfanew     DWORD ?
IMAGE_DOS_HEADER ENDS
ENDIF

.CONST
;------------------------------------------------------------------------------
; PE Constants
;------------------------------------------------------------------------------
PE_ALIGN                        TEXTEQU <ALIGN 16>
PE_INVALID                      EQU 0
PE_ARCH_32                      EQU 1
PE_ARCH_64                      EQU 2
PE32                            EQU PE_ARCH_32
PE64                            EQU PE_ARCH_64

; PE Error Enums:
PE_ERROR_SECTION_MOVE           EQU -14 ; Failed to move section
PE_ERROR_SECTION_INS            EQU -13 ; Failed to add and insert section to PE file
PE_ERROR_SECTION_DEL            EQU -12 ; Failed to delete section to PE file
PE_ERROR_SECTION_ADD            EQU -11 ; Failed to add section to PE file
PE_ERROR_ANALYZE_NULL           EQU -10 ; PE memory address is 0 or size is 0
PE_ERROR_ANALYZE_INVALID        EQU  -9 ; Invalid magic no or signature 
PE_ERROR_ANALYZE_ALLOC          EQU  -8 ; Could not allocate memory for initial analysis
PE_ERROR_OPEN_VIEW              EQU  -7 ; Could not map a view of PE file
PE_ERROR_OPEN_MAP               EQU  -6 ; Could not map PE file
PE_ERROR_OPEN_SIZE_HIGH         EQU  -5 ; File size too large to be a valid PE file
PE_ERROR_OPEN_SIZE_LOW          EQU  -4 ; File size too low to be a valid PE file
PE_ERROR_OPEN_FILE              EQU  -3 ; Error opening PE file
PE_ERROR_OPEN_INVALID           EQU  -2 ; Not a valid PE file 
PE_ERROR_NO_HANDLE              EQU  -1 ; No variable provided to store hPE in or hPE is null
PE_ERROR_SUCCESS                EQU   0 ; Success

; Signatures:
MZ_SIGNATURE                    EQU 5A4Dh ; ZM - 'MZ'
PE_SIGNATURE                    EQU 4550h ; EP - 'PE'
NE_SIGNATURE                    EQU 4E50h ; EN - 'NE'

; PE Magic Number:
IMAGE_NT_OPTIONAL_HDR32_MAGIC   EQU 010Bh ; The file is an executable image.
IMAGE_NT_OPTIONAL_HDR64_MAGIC   EQU 020Bh ; The file is an executable image.
IMAGE_ROM_OPTIONAL_HDR_MAGIC    EQU 0107h ; The file is a ROM image.

; Optional Header Structure Sizes:
SIZEOF_STANDARD_FIELDS_PE32     EQU 28d
SIZEOF_STANDARD_FIELDS_PE64     EQU 24d
SIZEOF_WINDOWS_FIELDS_PE32      EQU 68d
SIZEOF_WINDOWS_FIELDS_PE64      EQU 88d


;------------------------------------------------------------------------------
; MS-COFF defines:
;------------------------------------------------------------------------------
; Characteristics:
IMAGE_FILE_DLL                  EQU 2000h ; The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.

; Data Directory Indexes:
IMAGE_DIRECTORY_ENTRY_EXPORT    EQU  0 ; Export directory
IMAGE_NUMBEROF_DIRECTORY_ENTRIES EQU 16























