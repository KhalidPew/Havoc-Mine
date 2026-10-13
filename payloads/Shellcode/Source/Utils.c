#include <Utils.h>
#include <Macro.h>

SEC( text, B ) VOID CryptDecodeBuffer( PVOID Buffer, SIZE_T Length, PCHAR Key, SIZE_T KeyLen )
{
    ULONG State = 0x811c9dc5; // fnv1a basis, folded with the key bytes
    ULONG Stream = 0;

    for ( SIZE_T i = 0; i < KeyLen; i++ )
    {
        State ^= ( UCHAR ) Key[ i ];
        State *= 0x01000193;           // fnv1a prime
    }

    PBYTE Data = ( PBYTE ) Buffer;
    for ( SIZE_T i = 0; i < Length; i++ )
    {
        // mulberry32: cheap, allocation-free, register-only keystream
        State = State + 0x6D2B79F5;
        Stream = State;
        Stream = ( Stream ^ ( Stream >> 15 ) ) * ( Stream | 1 );
        Stream ^= Stream + ( ( Stream ^ ( Stream >> 7 ) ) * ( Stream | 61 ) );
        Data[ i ] ^= ( BYTE )( ( Stream ^ ( Stream >> 14 ) ) & 0xFF );
    }
}

SEC( text, B ) UINT_PTR HashString( LPVOID String, UINT_PTR Length )
{
    ULONG	Hash = 5381;
    PUCHAR	Ptr  = String;

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