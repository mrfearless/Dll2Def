;==============================================================================
;
; Dll2Def
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
;    Includelib M:\Masm32\lib\Debug32.lib
;    DBG32LIB equ 1
;    DEBUGEXE textequ <'M:\Masm32\DbgWin.exe'>
;    Include M:\Masm32\include\debug32.inc
;ENDIF


Include Dll2Def.inc
Include PELite.asm

.CODE


;------------------------------------------------------------------------------
; Entry
;------------------------------------------------------------------------------
Main PROC
    Invoke ConsoleStarted
    .IF eax == TRUE ; Started From Console

        Invoke ConsoleAttach
        Invoke ConsoleGetTitle, Addr szConTitle, SIZEOF szConTitle
        Invoke ConsoleSetTitle, Addr TitleName
        Invoke Dll2DefConInfo, CON_OUT_INFO
        ; Start main console processing
        Invoke Dll2DefMain
        ; Exit main console processing
        Invoke ConsoleSetTitle, Addr szConTitle
        Invoke ConsoleShowCursor
        Invoke ConsoleFree

    .ELSE ; Started From Explorer
        
	    Invoke ConsoleAttach
        Invoke ConsoleSetIcon, ICO_MAIN
        Invoke ConsoleSetTitle, Addr TitleName 
        Invoke Dll2DefConInfo, CON_OUT_INFO
        Invoke Dll2DefConInfo, CON_OUT_ABOUT
        Invoke ConsolePause, CON_PAUSE_ANY_KEY_EXIT
        Invoke ConsoleSetIcon, ICO_CMD
        Invoke ConsoleFree
        
    .ENDIF
    
    Invoke  ExitProcess,0
    ret
Main ENDP

;------------------------------------------------------------------------------
; Dll2DefMain
;------------------------------------------------------------------------------
Dll2DefMain PROC

    Invoke Dll2DefRegisterSwitches
    Invoke Dll2DefRegisterCommands    
    Invoke Dll2DefProcessCmdLine

    ;--------------------------------------------------------------------------
    ; HELP: /? help switch or no switch
    ;--------------------------------------------------------------------------
    .IF eax == CMDLINE_NOTHING || eax == CMDLINE_HELP ; no switch provided or /?

        Invoke Dll2DefConInfo, CON_OUT_HELP   

    ;--------------------------------------------------------------------------
    ; CMDLINE_FILEIN
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FILEIN
        Invoke Dll2Def_FilenameIn
    
    ;--------------------------------------------------------------------------
    ; CMDLINE_FILEIN_FILESPEC
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FILEIN_FILESPEC
        Invoke Dll2Def_FileSpecIn
    
    ;--------------------------------------------------------------------------
    ; CMDLINE_FILEIN_FILEOUT
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FILEIN_FILEOUT
        Invoke Dll2Def_FilenameIn_FilenameOut
    
    ;--------------------------------------------------------------------------
    ; CMDLINE_FOLDER_FILESPEC
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FOLDER_FILESPEC
        Invoke Dll2Def_FolderIn
        
    ;--------------------------------------------------------------------------
    ; CMDLINE_FILEIN_FILESPEC_FOLDEROUT
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FILEIN_FILESPEC_FOLDEROUT
        Invoke Dll2Def_FileSpecIn_FolderOut
    
    ;--------------------------------------------------------------------------
    ; CMDLINE_FOLDER_FILESPEC_FOLDEROUT
    ;--------------------------------------------------------------------------
    .ELSEIF eax == CMDLINE_FOLDER_FILESPEC_FOLDEROUT
        Invoke Dll2Def_FolderIn_FolderOut
        
    ;--------------------------------------------------------------------------
    ; ERROR
    ;--------------------------------------------------------------------------
    .ELSE
    
        Invoke Dll2DefConErr, eax
        
    .ENDIF
    
    ret
Dll2DefMain ENDP

;------------------------------------------------------------------------------
; Process command line information
;------------------------------------------------------------------------------
Dll2DefProcessCmdLine PROC
    LOCAL dwLenCmdLineParameter:DWORD
    LOCAL bFileIn:DWORD
    LOCAL bCommand:DWORD

    Invoke GetCommandLine
    Invoke ConsoleParseCmdLine, Addr CmdLineParameters
    mov TotalCmdLineParameters, eax ; will be at least 1 as param 0 is name of exe
    
   .IF TotalCmdLineParameters == 1 ; nothing extra specified
        mov eax, CMDLINE_NOTHING
        ret       
    .ENDIF       

    Invoke ConsoleCmdLineParam, Addr CmdLineParameters, 1, TotalCmdLineParameters, Addr CmdLineParameter
    .IF sdword ptr eax > 0
        mov dwLenCmdLineParameter, eax
    .ELSE
        mov eax, CMDLINE_ERROR
        ret
    .ENDIF
    
    ;--------------------------------------------------------------------------
    ; Dll2Def [switch|command] 
    ; Dll2Def FILENAMEIN 
    ; Dll2Def FILESPECIN
    ; Dll2Def FOLDERIN
    ;--------------------------------------------------------------------------    
    .IF TotalCmdLineParameters == 2
        
        Invoke ConsoleCmdLineParamType, Addr CmdLineParameters, 1, TotalCmdLineParameters
        .IF eax == CMDLINE_PARAM_TYPE_ERROR
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_ERROR'
            mov eax, CMDLINE_ERROR
            ret
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_UNKNOWN
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_UNKNOWN'
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_SWITCH
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_SWITCH'
            Invoke ConsoleSwitchID, Addr CmdLineParameter, FALSE
            .IF eax == SWITCH_HELP || eax == SWITCH_HELP_UNIX || eax == SWITCH_HELP_UNIX2 
                mov eax, CMDLINE_HELP
                ret
            ; User specified an unknown switch (one that isn't registered) : /x -x
            .ELSE
                mov eax, CMDLINE_UNKNOWN_SWITCH
                ret
            .ENDIF
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_COMMAND
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_COMMAND'
            Invoke ConsoleCommandID, Addr CmdLineParameter, FALSE
            ;PrintDec eax
            .IF eax == -1 
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ELSE
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ENDIF

        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILESPEC
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_FILESPEC'
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            mov eax, CMDLINE_FILEIN_FILESPEC
            ret            
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILENAME
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_FILENAME'
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            Invoke exist, Addr szDll2DefInFilename
            .IF eax == TRUE ; does exist
                mov eax, CMDLINE_FILEIN
                ret
            .ELSE
                mov eax, CMDLINE_FILEIN_NOT_EXIST
                ret
            .ENDIF
                
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FOLDER
            ;PrintText 'ConsoleCmdLineParamType CMDLINE_PARAM_TYPE_FOLDER'
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            Invoke exist, Addr szDll2DefInFilename
            .IF eax == TRUE ; does exist
                ; assume filespec of *.* in folder provided
                Invoke lstrcat, Addr szDll2DefInFilename, Addr szFolderAllFiles
                mov eax, CMDLINE_FOLDER_FILESPEC
                ret
            .ELSE
                mov eax, CMDLINE_FILEIN_NOT_EXIST
                ret
            .ENDIF
        .ENDIF
    .ENDIF

    ;--------------------------------------------------------------------------
    ; Dll2Def FILENAMEIN FILENAMEOUT
    ; Dll2Def FILESPECIN FOLDEROUT
    ; Dll2Def FOLDERIN FOLDEROUT
    ; Dll2Def [switch|command] FILENAMEIN
    ; Dll2Def [switch|command] FILESPECIN
    ; Dll2Def [switch|command] FOLDERIN
    ; Dll2Def [switch|command] [switch|command] 
    ; Dll2Def FILENAMEIN [switch|command] 
    ; Dll2Def FILESPECIN [switch|command] 
    ; Dll2Def FOLDERIN [switch|command] 
    ;--------------------------------------------------------------------------    
    mov bFileIn, FALSE

    
    .IF TotalCmdLineParameters == 3
        Invoke ConsoleCmdLineParamType, Addr CmdLineParameters, 1, TotalCmdLineParameters
        .IF eax == CMDLINE_PARAM_TYPE_ERROR
            mov eax, CMDLINE_ERROR
            ret    

        .ELSEIF eax == CMDLINE_PARAM_TYPE_UNKNOWN
        
        .ELSEIF eax == CMDLINE_PARAM_TYPE_SWITCH
            Invoke ConsoleSwitchID, Addr CmdLineParameter, FALSE
            .IF eax == SWITCH_HELP || eax == SWITCH_HELP_UNIX || eax == SWITCH_HELP_UNIX2 
                mov eax, CMDLINE_HELP
                ret
            .ELSE
                mov eax, CMDLINE_UNKNOWN_SWITCH
                ret
            .ENDIF
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_COMMAND
            Invoke ConsoleCommandID, Addr CmdLineParameter, FALSE
            .IF eax == -1 
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ELSE
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ENDIF
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILESPEC
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILENAME
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            Invoke exist, Addr szDll2DefInFilename
            .IF eax == TRUE ; does exist
                ;mov bFileIn, TRUE
                ;mov eax, CMDLINE_FILEIN
                ;ret
            .ELSE
                mov eax, CMDLINE_FILEIN_NOT_EXIST
                ret
            .ENDIF            
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FOLDER
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            Invoke exist, Addr szDll2DefInFilename
            .IF eax == TRUE ; does exist
                ; assume filespec of *.* in folder provided
                Invoke lstrcat, Addr szDll2DefInFilename, Addr szFolderAllFiles
            .ELSE
                mov eax, CMDLINE_FILEIN_NOT_EXIST
                ret
            .ENDIF            
            
        .ENDIF
        
        ; Get 2nd param
        Invoke ConsoleCmdLineParam, Addr CmdLineParameters, 2, TotalCmdLineParameters, Addr CmdLineParameter
        .IF sdword ptr eax > 0
            mov dwLenCmdLineParameter, eax
        .ELSE
            mov eax, CMDLINE_ERROR
            ret
        .ENDIF
        
        Invoke ConsoleCmdLineParamType, Addr CmdLineParameters, 2, TotalCmdLineParameters
        .IF eax == CMDLINE_PARAM_TYPE_ERROR
            mov eax, CMDLINE_ERROR
            ret
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_UNKNOWN
        
        .ELSEIF eax == CMDLINE_PARAM_TYPE_SWITCH
            Invoke ConsoleSwitchID, Addr CmdLineParameter, FALSE
            .IF eax == SWITCH_HELP || eax == SWITCH_HELP_UNIX || eax == SWITCH_HELP_UNIX2 
                mov eax, CMDLINE_HELP
                ret
            .ELSE
                mov eax, CMDLINE_UNKNOWN_SWITCH
                ret
            .ENDIF
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_COMMAND ; user specified filename/filespec/folder first then command?
            Invoke ConsoleCommandID, Addr CmdLineParameter, FALSE
            .IF eax == -1 
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ELSE
                mov eax, CMDLINE_UNKNOWN_COMMAND
                ret
            .ENDIF

        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILESPEC
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefInFilename, MAX_PATH
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefInFilename
            mov eax, CMDLINE_FILESPEC_NOT_SUPPORTED
            ret
            
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FILENAME
            ;Invoke szCopy, Addr CmdLineParameter, Addr szDll2DefOutFilename
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefOutFilename, MAX_PATH
            Invoke ConsoleCmdLineParamType, Addr CmdLineParameters, 1, TotalCmdLineParameters
            .IF eax == CMDLINE_PARAM_TYPE_FILENAME
                mov eax, CMDLINE_FILEIN_FILEOUT
                ret
            .ELSEIF eax == CMDLINE_PARAM_TYPE_FILESPEC
                mov eax, CMDLINE_FILESPEC_NOT_SUPPORTED
                ret
            .ELSEIF eax == CMDLINE_PARAM_TYPE_FOLDER
                mov eax, CMDLINE_FOLDER_NOT_SUPPORTED
                ret
            .ELSE
                mov eax, CMDLINE_ERROR
                ret
            .ENDIF
       
        .ELSEIF eax == CMDLINE_PARAM_TYPE_FOLDER
            Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefOutFilename, MAX_PATH
            Invoke ConsoleCmdLineParamType, Addr CmdLineParameters, 1, TotalCmdLineParameters
            .IF eax == CMDLINE_PARAM_TYPE_FILENAME
                ; output filein to a specific folder
                Invoke JustFname, Addr szDll2DefInFilename, Addr szDll2DefFilename
                Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT("\")
                Invoke lstrcat, Addr szDll2DefOutFilename, Addr szDll2DefFilename
                Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT(".def")
                mov eax, CMDLINE_FILEIN_FILEOUT
                ret
            .ELSEIF eax == CMDLINE_PARAM_TYPE_FILESPEC
                mov _g_OutputFolder, TRUE
                Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefOutFolder, MAX_PATH
                mov eax, CMDLINE_FILEIN_FILESPEC_FOLDEROUT
                ret
            .ELSEIF eax == CMDLINE_PARAM_TYPE_FOLDER
                mov _g_OutputFolder, TRUE
                Invoke ExpandEnvironmentStrings, Addr CmdLineParameter, Addr szDll2DefOutFolder, MAX_PATH
                mov eax, CMDLINE_FOLDER_FILESPEC_FOLDEROUT
                ret
            .ELSE
                mov eax, CMDLINE_ERROR
                ret
            .ENDIF
        
        .ENDIF

    .ENDIF    

    mov eax, CMDLINE_ERROR

    ret
Dll2DefProcessCmdLine ENDP

;------------------------------------------------------------------------------
; Register switches for use on command line
;------------------------------------------------------------------------------
Dll2DefRegisterSwitches PROC
    Invoke ConsoleSwitchRegister, Addr SwitchHelp, SWITCH_HELP
    Invoke ConsoleSwitchRegister, Addr SwitchHelpAlt, SWITCH_HELP_UNIX
    Invoke ConsoleSwitchRegister, Addr SwitchHelpAlt2, SWITCH_HELP_UNIX2
    ret
Dll2DefRegisterSwitches ENDP

;------------------------------------------------------------------------------
; Register commands for use on command line
;------------------------------------------------------------------------------
Dll2DefRegisterCommands PROC
    ret
Dll2DefRegisterCommands ENDP

;------------------------------------------------------------------------------
; Prints out console information
;------------------------------------------------------------------------------
Dll2DefConInfo PROC dwMsgType:DWORD
    mov eax, dwMsgType
    .IF eax == CON_OUT_INFO
    
        Invoke ConsoleStdOut, Addr szDll2DefConInfoStart
        Invoke ConsoleStdOutColor, Addr szDll2DefConName, FOREGROUND_INTENSE_WHITE
        Invoke ConsoleStdOut, Addr szDll2DefConInfoFinish  
    
        ;Invoke ConsoleStdOut, Addr szDll2DefConInfo
    .ELSEIF eax == CON_OUT_ABOUT
        Invoke ConsoleStdOut, Addr szDll2DefConAbout
    .ELSEIF eax == CON_OUT_USAGE
        Invoke ConsoleStdOut, Addr szDll2DefConHelpUsage
    .ELSEIF eax == CON_OUT_HELP
        ;Invoke ConsoleStdOut, Addr szDll2DefConHelp
        Invoke ConsoleStdOutColor, Addr szDll2DefConHelpUsage, FOREGROUND_INTENSE_WHITE
        Invoke ConsoleStdOut, Addr szDll2DefConHelp        
        
    .ENDIF
    ret
Dll2DefConInfo ENDP

;------------------------------------------------------------------------------
; Prints out error information to console
;------------------------------------------------------------------------------
Dll2DefConErr PROC dwErrorType:DWORD
    mov eax, dwErrorType
    .IF eax == CMDLINE_UNKNOWN_SWITCH || eax == CMDLINE_UNKNOWN_COMMAND || eax == CMDLINE_COMMAND_WITHOUT_FILEIN
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr CmdLineParameter
        Invoke ConsoleStdOut, Addr szSingleQuote
        mov eax, dwErrorType
        .IF eax == CMDLINE_UNKNOWN_SWITCH
            Invoke ConsoleStdOut, Addr szErrorUnknownSwitch
        .ELSEIF eax == CMDLINE_UNKNOWN_COMMAND
            Invoke ConsoleStdOut, Addr szErrorUnknownCommand
        .ELSEIF eax == CMDLINE_COMMAND_WITHOUT_FILEIN
            Invoke ConsoleStdOut, Addr szErrorCommandWithoutFile
        .ENDIF
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke Dll2DefConInfo, CON_OUT_USAGE
        
    .ELSEIF eax == CMDLINE_FILEIN_NOT_EXIST
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szDll2DefInFilename
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szErrorFilenameNotExist
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
        
    .ELSEIF eax == CMDLINE_ERROR
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szErrorOther
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
    
    .ELSEIF eax == ERROR_FILEIN_IS_EMPTY
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szDll2DefInFilename
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szErrorFileZeroBytes
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
        
    .ELSEIF eax == ERROR_OPENING_FILEIN
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szDll2DefInFilename
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szErrorOpeningInFile
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
            
    .ELSEIF eax == ERROR_CREATING_FILEOUT
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szDll2DefOutFilename
        Invoke ConsoleStdOut, Addr szSingleQuote
        Invoke ConsoleStdOut, Addr szErrorCreatingOutFile
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
    
    .ELSEIF eax == ERROR_ALLOC_MEMORY
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szErrorAllocMemory
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
    
    .ELSEIF eax == ERROR_ZERO_EXPORTS
        Invoke ConsoleStdOut, Addr szError
        Invoke ConsoleStdOut, Addr szErrorZeroExports
        Invoke ConsoleStdOut, Addr szCRLF
        Invoke ConsoleStdOut, Addr szCRLF
    .ENDIF
    ret
Dll2DefConErr ENDP

;------------------------------------------------------------------------------
; Process dllfilename
;------------------------------------------------------------------------------
Dll2Def_FilenameIn PROC
    Invoke Dll2DefProcess, Addr szDll2DefInFilename, NULL, g_OptionUseFilename, g_OptionRemoveUnderscore
    ret
Dll2Def_FilenameIn ENDP

;------------------------------------------------------------------------------
; Process dllfilename deffilename
;------------------------------------------------------------------------------
Dll2Def_FilenameIn_FilenameOut PROC
    Invoke Dll2DefProcess, Addr szDll2DefInFilename, Addr szDll2DefOutFilename, g_OptionUseFilename, g_OptionRemoveUnderscore
    ret
Dll2Def_FilenameIn_FilenameOut ENDP

;------------------------------------------------------------------------------
; Process *.*, *.dll etc
;------------------------------------------------------------------------------
Dll2Def_FileSpecIn PROC
    Invoke Dll2DefProcessBatch, Addr szDll2DefInFilename
    ret
Dll2Def_FileSpecIn ENDP

;------------------------------------------------------------------------------
; Process folder - assumes <foldername>\*.*
;------------------------------------------------------------------------------
Dll2Def_FolderIn PROC
    Invoke Dll2DefProcessBatch, Addr szDll2DefInFilename
    ret
Dll2Def_FolderIn ENDP

;------------------------------------------------------------------------------
; Process folder - assumes <foldername>\*.* to output folder
;------------------------------------------------------------------------------
Dll2Def_FolderIn_FolderOut PROC
    Invoke Dll2DefProcessBatch, Addr szDll2DefInFilename
    ret
Dll2Def_FolderIn_FolderOut ENDP

;------------------------------------------------------------------------------
; Process *.*, *.dll etc to output folder
;------------------------------------------------------------------------------
Dll2Def_FileSpecIn_FolderOut PROC
    Invoke Dll2DefProcessBatch, Addr szDll2DefInFilename
    ret
Dll2Def_FileSpecIn_FolderOut ENDP

;------------------------------------------------------------------------------
; Create Def file from Dll file
;------------------------------------------------------------------------------
Dll2DefProcess PROC lpszDllFilename:DWORD, lpszDefFilename:DWORD, bUseFilename:DWORD, bRemoveUnderscore:DWORD
    LOCAL hPE:DWORD

    Invoke ConsoleStdOut, Addr szInFile
    Invoke ConsoleStdOut, lpszDllFilename
    Invoke ConsoleStdOut, Addr szCRLF

    Invoke PE_OpenFile, lpszDllFilename, TRUE, Addr hPE
    .IF eax == FALSE
        ; error not a pe file
        Invoke Dll2DefConErr, ERROR_OPENING_FILEIN
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_ExportNameCount, hPE
    .IF eax == 0
        ; error - no functions to export
        Invoke ConsoleStdOut, Addr szInfo
        Invoke ConsoleStdOut, Addr szErrorZeroExports
        Invoke ConsoleStdOut, Addr szCRLF
        xor eax, eax
        ret
    .ENDIF
    mov ExportedFunctionCount, eax
    
    .IF lpszDefFilename == NULL
	    Invoke GetCurrentDirectory, MAX_PATH, Addr szDll2DefOutFilename
	    Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT("\")
	    Invoke JustFname, Addr szDll2DefInFilename, Addr szDll2DefFilename
	    Invoke lstrcat, Addr szDll2DefOutFilename, Addr szDll2DefFilename
	    Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT(".def")
        Invoke ConsoleStdOut, Addr szOutFile
        Invoke ConsoleStdOut, Addr szDll2DefOutFilename
        Invoke ConsoleStdOut, Addr szCRLF
        ; Output def file
        Invoke PE_ExportFunctionNameToDef, hPE, Addr szDll2DefOutFilename, bUseFilename, bRemoveUnderscore ; defaults to creating .\filename.def
	.ELSE
        Invoke ConsoleStdOut, Addr szOutFile
        Invoke ConsoleStdOut, lpszDefFilename
        Invoke ConsoleStdOut, Addr szCRLF
        ; Output def file
        Invoke PE_ExportFunctionNameToDef, hPE, lpszDefFilename, bUseFilename, bRemoveUnderscore ; defaults to creating .\filename.def
	.ENDIF
    .IF eax == FALSE
        Invoke PE_CloseFile, hPE
        Invoke Dll2DefConErr, ERROR_CREATING_FILEOUT
        xor eax, eax
        ret
    .ENDIF
    
    Invoke PE_CloseFile, hPE
    
    ; tell user that we have processed file
    Invoke ConsoleStdOut, Addr szInfo
    Invoke ConsoleStdOut, Addr szSuccessExport
    Invoke dwtoa, ExportedFunctionCount, Addr szExportedFunctionCount
    Invoke ConsoleStdOut, Addr szExportedFunctionCount
    Invoke ConsoleStdOut, Addr szSuccessFunctions
    Invoke ConsoleStdOut, Addr szCRLF
    
    mov eax, TRUE
    ret
Dll2DefProcess ENDP

;------------------------------------------------------------------------------
; Create Def file from Dll file - batch processing
;------------------------------------------------------------------------------
Dll2DefProcessBatch PROC USES EBX FileSpec:DWORD
    LOCAL WFD:WIN32_FIND_DATA
    LOCAL hFind:DWORD
    LOCAL bContinueFind:DWORD
    LOCAL nFileCount:DWORD
    LOCAL nFileFailCount:DWORD
    
    ; get first file
    Invoke FindFirstFile, FileSpec, Addr WFD
    .IF eax == INVALID_HANDLE_VALUE
        Invoke GetLastError
        ;PrintDec eax
        mov eax, FALSE
        ret
    .ENDIF    
    mov hFind, eax
	mov bContinueFind, TRUE
    
	lea ebx, WFD.cFileName
	.IF byte ptr [ebx] == '.' && byte ptr [ebx+1] == 0 ;entry == "."
		;"." entry found means NOT ROOT directory and next entry MUST BE ".."
		;so...eat the ".." entry up :)
		Invoke FindNextFile, hFind, Addr WFD
		;make the scan point to the first valid file/directory (if any) :)
		Invoke FindNextFile, hFind, Addr WFD
		mov bContinueFind, eax
	.ENDIF    
  
    mov nFileCount, 0
    mov nFileFailCount, 0
    
    ; start loop
    .WHILE bContinueFind == TRUE
		mov eax, WFD.dwFileAttributes
		and eax, FILE_ATTRIBUTE_DIRECTORY
		.IF eax != FILE_ATTRIBUTE_DIRECTORY
		    
		    Invoke szCopy, Addr WFD.cFileName, Addr szDll2DefInFilename
		    
		    .IF _g_OutputFolder == TRUE
		        Invoke lstrcpy, Addr szDll2DefOutFilename, Addr szDll2DefOutFolder
		    .ELSE
		        Invoke GetCurrentDirectory, MAX_PATH, Addr szDll2DefOutFilename
		    .ENDIF
		    Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT("\")
		    Invoke JustFname, Addr szDll2DefInFilename, Addr szDll2DefFilename
		    Invoke lstrcat, Addr szDll2DefOutFilename, Addr szDll2DefFilename
		    Invoke lstrcat, Addr szDll2DefOutFilename, CTEXT(".def")
		    
		    Invoke Dll2DefProcess, Addr szDll2DefInFilename, Addr szDll2DefOutFilename, g_OptionUseFilename, g_OptionRemoveUnderscore
		    .IF eax == TRUE
		        inc nFileCount
		    .ELSE
		        inc nFileFailCount
		    .ENDIF
		.ENDIF
		
		Invoke FindNextFile, hFind, Addr WFD
	    mov bContinueFind, eax
	.ENDW
    Invoke FindClose, hFind
    
    mov eax, nFileCount
    mov ebx, nFileFailCount
    .IF eax == 0 && ebx == 0 ; no files processed
        Invoke ConsoleStdOut, Addr szDll2DefConBatchNoFiles
    .ELSEIF eax == 0 && ebx != 0 ; errors occured
        Invoke ConsoleStdOut, Addr szDll2DefConBatchFail
    .ELSEIF eax != 0 && ebx != 0 ; partial success and errors
        Invoke ConsoleStdOut, Addr szDll2DefConBatchPartial
    .ELSEIF eax != 0 && ebx == 0 ; success
        Invoke ConsoleStdOut, Addr szDll2DefConBatchSuccess
    .ENDIF
    
    ret
Dll2DefProcessBatch ENDP

;**************************************************************************
; Strip path name to just filename Without extention
;**************************************************************************
JustFname PROC USES ESI EDI szFilePathName:DWORD, szFileName:DWORD
	LOCAL LenFilePathName:DWORD
	LOCAL nPosition:DWORD
	
	Invoke szLen, szFilePathName
	mov LenFilePathName, eax
	mov nPosition, eax
	
	.IF LenFilePathName == 0
	    mov edi, szFileName
		mov byte ptr [edi], 0
		mov eax, FALSE
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
	mov eax, TRUE
	ret
JustFname	ENDP

END Main







