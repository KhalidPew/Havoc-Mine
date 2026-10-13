#include <windows.h>

UINT_PTR HashString( LPVOID String, UINT_PTR Length );
VOID     CryptDecodeBuffer( PVOID Buffer, SIZE_T Length, PCHAR Key, SIZE_T KeyLen );