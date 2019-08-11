;==============================================================================
;
; Dll2Def
;
;==============================================================================
include windows.inc
include user32.inc
include kernel32.inc
include shell32.inc
include masm32.inc
includelib user32.lib
includelib kernel32.lib
includelib shell32.lib
includelib masm32.lib

include Console.inc
includelib Console.lib


;------------------------------------------------------------------------------
; Dll2Def Prototypes
;------------------------------------------------------------------------------
Dll2DefMain                     PROTO
Dll2DefRegisterSwitches         PROTO
Dll2DefRegisterCommands         PROTO
Dll2DefProcessCmdLine           PROTO

Dll2DefConInfo                  PROTO :DWORD
Dll2DefConErr                   PROTO :DWORD

Dll2Def_FilenameIn              PROTO
Dll2Def_FileSpecIn              PROTO
Dll2Def_FilenameIn_FilenameOut  PROTO
Dll2Def_FolderIn                PROTO
Dll2Def_FolderIn_FolderOut      PROTO
Dll2Def_FileSpecIn_FolderOut    PROTO

Dll2DefProcess                  PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dll2DefProcessBatch             PROTO :DWORD

JustFname                       PROTO :DWORD,:DWORD
IFNDEF GetCommandLineA
GetCommandLineA                 PROTO 
GetCommandLine                  EQU <GetCommandLineA>
ENDIF


.CONST
;------------------------------------------------------------------------------
; Dll2Def Constants
;------------------------------------------------------------------------------
ICO_MAIN                        EQU 100
ICO_CMD                         EQU 101

; Dll2DefConInfo dwMsgType:
CON_OUT_INFO                    EQU 0   ; Header information
CON_OUT_ABOUT                   EQU 1   ; About information
CON_OUT_USAGE                   EQU 2   ; Usage information: switches/commands and params
CON_OUT_HELP                    EQU 3   ; Help information

; Constants for Dll2DefProcessCmdLine
; return values and for Dll2DefConErr
; dwErrorType:

ERROR_ZERO_EXPORTS              EQU -14
ERROR_ALLOC_MEMORY              EQU -13 ; GlobalAlloc failed for some reason
ERROR_CREATING_FILEOUT          EQU -12 ; Couldnt create temporary output file
ERROR_OPENING_FILEIN            EQU -11 ; Couldnt open input filename
ERROR_FILEIN_IS_EMPTY           EQU -10 ; 0 byte file
CMDLINE_COMMAND_WITHOUT_FILEIN  EQU -9  ; User forgot to supply a filename or filespec or folder with command
CMDLINE_SWITCH_WITHOUT_FILEIN   EQU -8  ; User forgot to supply a filename or filespec or folder with command
CMDLINE_FOLDER_NOT_SUPPORTED    EQU -6  ; A folder (assumes <foldername>\*.* filespec) provided whilst supplying output filename
CMDLINE_FILESPEC_NOT_SUPPORTED  EQU -5  ; Using *.* etc wildcards whilst supplying output filename
CMDLINE_FILEIN_NOT_EXIST        EQU -4  ; Filename or filepath provided does not exist
CMDLINE_ERROR                   EQU -3  ; General error reading parameters
CMDLINE_UNKNOWN_COMMAND         EQU -2  ; User provided a <X> command that wasnt recognised
CMDLINE_UNKNOWN_SWITCH          EQU -1  ; User provided a /<X> or -<X> switch that wasnt recognised
CMDLINE_NOTHING                 EQU 0   ;
CMDLINE_HELP                    EQU 1   ; User specified /? -? --? as a parameter
CMDLINE_FILEIN                  EQU 2   ; A single filename was specified
CMDLINE_FILEIN_FILESPEC         EQU 3   ; A filespec (*.*, *.txt) was specified
CMDLINE_FILEIN_FILEOUT          EQU 4   ; A filename for input and a filename for output was specified
CMDLINE_FOLDER_FILESPEC         EQU 5   ; A folder was specified (assumes <foldername>\*.* filespec)
CMDLINE_FILEIN_FILESPEC_FOLDEROUT EQU 6 ; A filespec (*.*, *.txt) was specified AND a folder for output
CMDLINE_FOLDER_FILESPEC_FOLDEROUT EQU 7 ; A folder was specified (assumes <foldername>\*.* filespec) AND a folder for output

; Dll2Def Switch IDs: /? -? --? /f -f
SWITCH_HELP                     EQU 0   ; /? help switch
SWITCH_HELP_UNIX                EQU 1   ; -? help switch
SWITCH_HELP_UNIX2               EQU 2   ; --? help switch


.DATA
;------------------------------------------------------------------------------
; Dll2Def Initialized Data
;------------------------------------------------------------------------------
AppName                         DB 'Dll2Def',0
TitleName                       DB 'Dll2Def Tool v1.0.0.0',0
szConTitle                      DB MAX_PATH DUP (0)
CmdLineParameters               DB 512 DUP (0)
CmdLineParameter                DB 256 DUP (0)
ErrParameter                    DB 256 DUP (0)
TotalCmdLineParameters          DD 0

; Help
szDll2DefConName                DB "Dll2Def",0
szDll2DefConInfoStart           DB 13,10,"[",0
szDll2DefConInfoFinish          DB "] v1.00 - Create an export defintion file from a Dll - 2019 fearless",13,10,13,10,0

szDll2DefConInfo                DB 13,10,"[Dll2Def] v1.00 - Create an export defintion file from a Dll - 2019 fearless",13,10,13,10,0

szDll2DefConAbout               DB "About:",13,10
                                DB "========",13,10
                                DB "Dll2Def is a console program which needs to be ran from a command prompt.",13,10
                                DB "For detailed help on the Dll2Def options, specify Dll2Def /? at the prompt.",13,10
                                DB 13,10,13,10
                                DB 13,10,0

szDll2DefConHelp                DB 13,10
                                DB "  Switches:",13,10     
                                DB 13,10
                                DB "  /? | -?       Displays this help.",13,10
                                DB 13,10
                                DB 13,10
                                DB "  Parameters:",13,10
                                DB 13,10
                                DB "  <infilename>  name of a valid dll file to process.",13,10
                                DB "                Supports the use of wildcards * and ? for batch operations.",13,10
                                DB 13,10
                                DB "  <outfilename> (optional) is name of the definiton file",13,10
                                DB "                to create. Defaults to the dllfilename with .def extension.",13,10
                                DB "                Note: cannot use wildcards if specifying outfilename.",13,10
                                DB 13,10
                                DB "  <infilespec>  is the use of wildcards (*.dll) to process.",13,10
                                DB 13,10
                                DB "  <outfolder>   (optional) is the folder to output .def files to.",13,10
                                DB 13,10
                                DB "  <infolder>    (optional) is the folder to process. (Assumes *.*)",13,10
                                DB 13,10
                                DB 13,10
                                DB 13,10,0

szDll2DefConHelpUsage           DB "  Usage:        Dll2Def [ /? | -? ]",13,10
                                DB "                Dll2Def <infilename> [<outfilename>]",13,10
                                DB "                Dll2Def <infilespec> [<outfolder>]",13,10
                                DB "                Dll2Def <infolder> [<outfolder>]",13,10
                                DB 13,10,0


szSuccessExport                 DB "Exported ",0
ExportedFunctionCount           DD 0
szExportedFunctionCount         DB 16 DUP (0)
szSuccessFunctions              DB " functions.",0
szInFileSpec                    DB "[=] Filespec: ",0
szInFile                        DB "[<] ",0
szOutFile                       DB "[>] ",0
szInfo                          DB "[i] ",0
szDll2DefConBatchNoFiles        DB 13,10,"[ ] Finished: no files where processed for current operation.",13,10,0
szDll2DefConBatchSuccess        DB 13,10,"[=] Finished: operation on all files successfull.",13,10,0
szDll2DefConBatchFail           DB 13,10,"[x] Finished: operation on all files failed!",13,10,0
szDll2DefConBatchPartial        DB 13,10,"[i] Finished: operation on some files failed.",13,10,0

; Error message
szError                         DB "[!] Error: ",0
szErrorUnknownSwitch            DB " invalid switch specified.",0
szErrorUnknownCommand           DB " invalid command specified.",0
szErrorCommandWithoutFile       DB " command specified but no filename or filespec provided.",0
szErrorFileSpecNotSupported     DB " wildcard filespec not supported for input file(s) when also specifying output filename as well.",0
szErrorFilenameNotExist         DB " filename/filepath does not exist.",0
szErrorOther                    DB "unknown error occured whilst parsing parameters and switches.",0
szErrorFolderNotSupported       DB " folder (assumes *.*) not supported for input file(s) when also specifying output filename as well.",0
szErrorFileZeroBytes            DB " file 0 bytes, skipping.",0
szErrorOpeningInFile            DB " failed to open input file, or not a valid exe/dll file.",0
szErrorCreatingOutFile          DB " failed to create .def file.",0
szErrorAllocMemory              DB "failed to allocate memory for operation.",0
szErrorZeroExports              DB "zero exports in PE file.",0

; Punctuation
szComma                         DB ',',0
szSpace                         DB ' ',0
szColon                         DB ':',0
szLeftBracket                   DB '{',0
szRightBracket                  DB '}',0
szBackslash                     DB '\',0
szLeftSquareBracket             DB '[',0
szRightSquareBracket            DB ']',0
szQuote                         DB '"',0
szSingleQuote                   DB "'",0
szDash                          DB '-',0
szForwardslash                  DB '/',0
szWildCardStar                  DB '*',0
szWildCardQuestion              DB '?',0
szLF                            DB 10,0
szCRLF                          DB 13,10,0
szFolderAllFiles                DB '\*.*',0

SwitchHelp                      DB '/?',0
SwitchHelpAlt                   DB '-?',0
SwitchHelpAlt2                  DB '--?',0

g_OptionUseFilename             DD TRUE
g_OptionRemoveUnderscore        DD FALSE
_g_OutputFolder                 DD FALSE




; Filename Buffers
szDll2DefFilename               DB MAX_PATH DUP (0)
szDll2DefInFilename             DB MAX_PATH DUP (0)
szDll2DefOutFilename            DB MAX_PATH DUP (0)
szDll2DefOutFolder              DB MAX_PATH DUP (0)

.DATA?
;------------------------------------------------------------------------------
; Dll2Def Uninitialized Data
;------------------------------------------------------------------------------
hFileIn                         DD ?
hMemMapIn                       DD ?
hMemMapInPtr                    DD ?
hFileOut                        DD ?
hMemMapOut                      DD ?
hMemMapOutPtr                   DD ?
qwFileSize                      DQ ?
dwFileSize                      DD ?
dwFileSizeHigh                  DD ?



















