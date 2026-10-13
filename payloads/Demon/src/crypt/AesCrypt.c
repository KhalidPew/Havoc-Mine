#include <crypt/AesCrypt.h>
#include <core/MiniStd.h>

#define Nb 4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
    #define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
    #define Nr 12
#else
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.
#endif

#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

typedef UINT8 dabba[4][4];

static const UINT8 boxy[256] = {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const UINT8 valhoti[11] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define nilenival(num) (boxy[(num)])

void keywaddikro(UINT8* chabi, const UINT8* Key)
{
    unsigned i, j, k;
    UINT8 faltu[4];

    for (i = 0; i < Nk; ++i)
    {
        chabi[(i * 4) + 0] = Key[(i * 4) + 0];
        chabi[(i * 4) + 1] = Key[(i * 4) + 1];
        chabi[(i * 4) + 2] = Key[(i * 4) + 2];
        chabi[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            faltu[0]=chabi[k + 0];
            faltu[1]=chabi[k + 1];
            faltu[2]=chabi[k + 2];
            faltu[3]=chabi[k + 3];

        }

        if (i % Nk == 0)
        {
            const UINT8 u8tmp = faltu[0];
            faltu[0] = faltu[1];
            faltu[1] = faltu[2];
            faltu[2] = faltu[3];
            faltu[3] = u8tmp;

            faltu[0] = nilenival(faltu[0]);
            faltu[1] = nilenival(faltu[1]);
            faltu[2] = nilenival(faltu[2]);
            faltu[3] = nilenival(faltu[3]);

            faltu[0] = faltu[0] ^ valhoti[i/Nk];
        }

        if (i % Nk == 4)
        {
            faltu[0] = nilenival(faltu[0]);
            faltu[1] = nilenival(faltu[1]);
            faltu[2] = nilenival(faltu[2]);
            faltu[3] = nilenival(faltu[3]);
        }

        j = i * 4; k=(i - Nk) * 4;
        chabi[j + 0] = chabi[k + 0] ^ faltu[0];
        chabi[j + 1] = chabi[k + 1] ^ faltu[1];
        chabi[j + 2] = chabi[k + 2] ^ faltu[2];
        chabi[j + 3] = chabi[k + 3] ^ faltu[3];
    }
}

void AesInit( PAESCTX ctx, const PUINT8 key, const PUINT8 iv)
{
  keywaddikro( ctx->chabi, key );
  MemCopy( ctx->Iv, iv, AES_BLOCKLEN );
}




static void ApplyKeyTransformation(UINT8 cycle, dabba* kenue, const UINT8* expandedKey)
{
    const UINT8* currentKey = expandedKey + ((size_t)cycle * 16);

    (*kenue)[0][0] ^= currentKey[0];
    (*kenue)[0][1] ^= currentKey[1];
    (*kenue)[0][2] ^= currentKey[2];
    (*kenue)[0][3] ^= currentKey[3];

    (*kenue)[1][0] ^= currentKey[4];
    (*kenue)[1][1] ^= currentKey[5];
    (*kenue)[1][2] ^= currentKey[6];
    (*kenue)[1][3] ^= currentKey[7];

    (*kenue)[2][0] ^= currentKey[8];
    (*kenue)[2][1] ^= currentKey[9];
    (*kenue)[2][2] ^= currentKey[10];
    (*kenue)[2][3] ^= currentKey[11];

    (*kenue)[3][0] ^= currentKey[12];
    (*kenue)[3][1] ^= currentKey[13];
    (*kenue)[3][2] ^= currentKey[14];
    (*kenue)[3][3] ^= currentKey[15];
}

// The SubBytes Function Substitutes the values in the
// state kenue with values in an S-box.
static void SubBytes(dabba* state)
{
    UINT8 i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = nilenival((*state)[j][i]);
        }
    }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(dabba* state)
{
    UINT8 temp;

    // Rotate first row 1 columns to left
    temp           = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    // Rotate second row 2 columns to left
    temp           = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp           = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    // Rotate third row 3 columns to left
    temp           = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static UINT8 xtime(UINT8 x)
{
    return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state kenue
static void MixColumns(dabba* state)
{
    UINT8 i;
    UINT8 Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t   = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
        Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
        Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
    }
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(dabba* state, const UINT8* chabi) // Main
{
    UINT8 round = 0;

    // Add the First round key to the state before starting the rounds.
    ApplyKeyTransformation(0, state, chabi);

    // There will be Nr rounds.
    // The first Nr-1 rounds are identical.
    // These Nr rounds are executed in the loop below.
    // Last one without MixColumns()
    for (round = 1; ; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr) {
            break;
        }
        MixColumns(state);
        ApplyKeyTransformation(round, state, chabi);
    }
    // Add round key to last round
    ApplyKeyTransformation(Nr, state, chabi);
}

#if defined(CTR) && (CTR == 1)

void AesXCryptBuffer( PAESCTX ctx, PUINT8 buf, SIZE_T length)
{
    UINT8 buffer[AES_BLOCKLEN];

    size_t i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN) /* we need to regen xor compliment in buffer */
        {
            MemCopy(buffer, ctx->Iv, AES_BLOCKLEN);
            Cipher((dabba*)buffer,ctx->chabi);

            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                if (ctx->Iv[bi] == 255)
	            {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }
        buf[i] = (buf[i] ^ buffer[bi]);
  }
}

#endif