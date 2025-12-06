#include "speck.h"
#include <string.h>

#define ROTL32(x,r) (((x) << (r)) | ((x) >> (32-(r))))
#define ROTR32(x,r) (((x) >> (r)) | ((x) << (32-(r))))
#define ROTL64(x,r) (((x) << (r)) | ((x) >> (64-(r))))
#define ROTR64(x,r) (((x) >> (r)) | ((x) << (64-(r))))

#define ROUNDS 27

static void speck_encrypt_block(const speck_context_t *ctx,
                                uint64_t *c, const uint64_t *p) {
    uint64_t x = p[0];
    uint64_t y = p[1];

    for (int i = 0; i < ROUNDS; i++) {
        x = (ROTL64(x, 8) + y) ^ ctx->key[i];
        y = ROTL64(y, 3) ^ x;
    }

    c[0] = x;
    c[1] = y;
}

int speck_expand_key(const unsigned char *k, speck_context_t *ctx) {
    uint64_t key[4];
    uint64_t i, j;

    // Load 256-bit key
    memcpy(key, k, 32);

    // Key expansion
    for (i = 0; i < ROUNDS; i++) {
        ctx->key[i] = key[0];
        key[0] = ROTL64(key[0], 8) + key[1];
        key[1] = ROTL64(key[1], 3) ^ key[0];
        key[0] = ROTL64(key[0], 8) + key[1];
        key[1] = ROTL64(key[1], 3) ^ key[0];

        if (i % 2 == 1) {
            key[2] = ROTL64(key[2], 8) + key[3];
            key[3] = ROTL64(key[3], 3) ^ key[2];
            key[2] = ROTL64(key[2], 8) + key[3];
            key[3] = ROTL64(key[3], 3) ^ key[2];
        }
    }

    return 0;
}

int speck_ctr(unsigned char *out, const unsigned char *in,
              unsigned long long inlen, const unsigned char *n,
#if defined (SPECK_CTX_BYVAL)
              speck_context_t ctx) {
#else
              speck_context_t *ctx) {
#endif
    uint64_t counter;
    uint64_t keystream[2];
    uint64_t plaintext[2];
    uint64_t ciphertext[2];

    memcpy(&counter, n, 8);

    for (unsigned long long i = 0; i < inlen; i += 16) {
        // Encrypt counter to get keystream
        plaintext[0] = counter;
        plaintext[1] = 0;

#if defined (SPECK_CTX_BYVAL)
        speck_encrypt_block(&ctx, keystream, plaintext);
#else
        speck_encrypt_block(ctx, keystream, plaintext);
#endif

        // XOR with plaintext
        for (int j = 0; j < 16 && (i + j) < inlen; j++) {
            out[i + j] = in[i + j] ^ ((unsigned char*)keystream)[j];
        }

        counter++;
    }

    return 0;
}
