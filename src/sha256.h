#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

typedef struct
{
        uint32_t        State[8];
        uint64_t        Count;
        uint8_t         Buffer[64];
} SHA256Context;

void    SHA256_Init     (SHA256Context *ctx);
void    SHA256_Update   (SHA256Context *ctx, const uint8_t *data, size_t len);
void    SHA256_Final    (SHA256Context *ctx, uint8_t out[32]);
void    SHA256          (const uint8_t *data, size_t len, uint8_t out[32]);

#endif
