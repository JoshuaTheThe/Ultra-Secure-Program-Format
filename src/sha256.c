#include "sha256.h"
#include <string.h>

static const uint32_t K[64] =
{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROTR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z)(((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)      (ROTR(x,  2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)      (ROTR(x,  6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)     (ROTR(x,  7) ^ ROTR(x, 18) ^ ((x) >>  3))
#define SIG1(x)     (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void SHA256_Transform(SHA256Context *ctx, const uint8_t data[64])
{
        uint32_t a, b, c, d, e, f, g, h;
        uint32_t w[64];
        uint32_t t1, t2;

        for (int i = 0; i < 16; i++)
        {
                w[i]  = (uint32_t)data[i * 4    ] << 24;
                w[i] |= (uint32_t)data[i * 4 + 1] << 16;
                w[i] |= (uint32_t)data[i * 4 + 2] <<  8;
                w[i] |= (uint32_t)data[i * 4 + 3];
        }
        for (int i = 16; i < 64; i++)
                w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];

        a = ctx->State[0];
        b = ctx->State[1];
        c = ctx->State[2];
        d = ctx->State[3];
        e = ctx->State[4];
        f = ctx->State[5];
        g = ctx->State[6];
        h = ctx->State[7];

        for (int i = 0; i < 64; i++)
        {
                t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
                t2 = EP0(a) + MAJ(a, b, c);
                h = g; g = f; f = e; e = d + t1;
                d = c; c = b; b = a; a = t1 + t2;
        }

        ctx->State[0] += a;
        ctx->State[1] += b;
        ctx->State[2] += c;
        ctx->State[3] += d;
        ctx->State[4] += e;
        ctx->State[5] += f;
        ctx->State[6] += g;
        ctx->State[7] += h;
}

void SHA256_Init(SHA256Context *ctx)
{
        ctx->Count     = 0;
        ctx->State[0]  = 0x6a09e667;
        ctx->State[1]  = 0xbb67ae85;
        ctx->State[2]  = 0x3c6ef372;
        ctx->State[3]  = 0xa54ff53a;
        ctx->State[4]  = 0x510e527f;
        ctx->State[5]  = 0x9b05688c;
        ctx->State[6]  = 0x1f83d9ab;
        ctx->State[7]  = 0x5be0cd19;
}

void SHA256_Update(SHA256Context *ctx, const uint8_t *data, size_t len)
{
        size_t i = 0;
        size_t used = ctx->Count % 64;

        ctx->Count += len;

        if (used)
        {
                size_t fill = 64 - used;
                if (len < fill)
                {
                        memcpy(ctx->Buffer + used, data, len);
                        return;
                }
                memcpy(ctx->Buffer + used, data, fill);
                SHA256_Transform(ctx, ctx->Buffer);
                i = fill;
        }

        for (; i + 64 <= len; i += 64)
                SHA256_Transform(ctx, data + i);

        if (i < len)
                memcpy(ctx->Buffer, data + i, len - i);
}

void SHA256_Final(SHA256Context *ctx, uint8_t out[32])
{
        uint8_t pad[64] = {0};
        size_t  used    = ctx->Count % 64;
        uint64_t bitlen = ctx->Count * 8;

        pad[0] = 0x80;

        if (used < 56)
                SHA256_Update(ctx, pad, 56 - used);
        else
                SHA256_Update(ctx, pad, 64 + 56 - used);

        // append length as big-endian 64-bit
        uint8_t len_bytes[8];
        for (int i = 7; i >= 0; i--)
        {
                len_bytes[i] = bitlen & 0xff;
                bitlen >>= 8;
        }
        SHA256_Update(ctx, len_bytes, 8);

        for (int i = 0; i < 8; i++)
        {
                out[i * 4    ] = (ctx->State[i] >> 24) & 0xff;
                out[i * 4 + 1] = (ctx->State[i] >> 16) & 0xff;
                out[i * 4 + 2] = (ctx->State[i] >>  8) & 0xff;
                out[i * 4 + 3] = (ctx->State[i]      ) & 0xff;
        }
}

void SHA256(const uint8_t *data, size_t len, uint8_t out[32])
{
        SHA256Context ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, data, len);
        SHA256_Final(&ctx, out);
}
