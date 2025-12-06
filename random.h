/**
 * @brief Cryptographic random number generator
 *
 * @file random.h
 * @author Max Resch <resch.max@gmail.com>
 */

#ifndef N2N_RANDOM_H_
#define N2N_RANDOM_H_

#if __linux__
// linux supports syscall random
#include <sys/random.h>
#elif __unix__
// BSD has arc4random
#include <stdlib.h>
#endif


#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32) && !defined(USE_BCRYPT)
#define USE_BCRYPT 1
#endif

#if USE_OPENSSL
#include <openssl/rand.h>
#elif USE_NETTLE
#include <nettle/yarrow.h>
#elif USE_GCRYPT
#include <gcrypt.h>
#elif USE_MBEDTLS
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/entropy_poll.h>
#elif USE_ELL
#include <ell/random.h>
#elif USE_BCRYPT
#include <windows.h>
#include <bcrypt.h>
#endif

typedef struct random_ctx {
#if USE_NETTLE
    struct yarrow256_ctx     yarrow;
#elif USE_MBEDTLS
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context random;
#elif USE_BCRYPT
    BCRYPT_ALG_HANDLE        hRandom;
#endif
} *random_ctx_t;

static inline void random_init(random_ctx_t ctx) {
#if USE_NETTLE
    yarrow256_init(&ctx->yarrow, 0, NULL);
    uint8_t rnd_data[YARROW256_SEED_FILE_SIZE];
    #if __linux__
    getrandom(rnd_data, YARROW256_SEED_FILE_SIZE, 0);
    #else
    arc4random_buf(rnd_data, YARROW256_SEED_FILE_SIZE);
    #endif
    yarrow256_seed(&ctx->yarrow, YARROW256_SEED_FILE_SIZE, rnd_data);
#elif USE_MBEDTLS
    mbedtls_ctr_drbg_init(&ctx->random);
    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_entropy_add_source(&ctx->entropy, &mbedtls_platform_entropy_poll, NULL, 16, MBEDTLS_ENTROPY_SOURCE_STRONG);
    mbedtls_ctr_drbg_seed(&ctx->random, &mbedtls_entropy_func, &ctx->entropy, NULL, 0);
#elif USE_BCRYPT
    BCryptOpenAlgorithmProvider (&ctx->hRandom, BCRYPT_RNG_ALGORITHM, NULL, 0);
#endif
}

static inline void random_free(random_ctx_t ctx) {
#if USE_MBEDTLS
    mbedtls_ctr_drbg_free(&ctx->random);
    mbedtls_entropy_free(&ctx->entropy);
#elif USE_BCRYPT
    BCryptCloseAlgorithmProvider(ctx->hRandom, 0);
#endif
}

static inline void random_bytes(random_ctx_t ctx, uint8_t* buffer, size_t size) {
#if USE_OPENSSL
    RAND_bytes((void*) buffer, size);
#elif USE_GCRYPT
    gcry_create_nonce(buffer, size);
#elif USE_NETTLE
    yarrow256_random(&ctx->yarrow, size, buffer);
#elif USE_MBEDTLS
    mbedtls_ctr_drbg_random(&ctx->random, buffer, (uint32_t) size);
#elif USE_ELL
    l_getrandom(buffer, (uint32_t) size);
#elif USE_BCRYPT
    BCryptGenRandom(ctx->hRandom, buffer, (uint32_t) size, 0);
#elif __linux__
    getrandom(buffer, size, 0);
#elif __unix__
    arc4random_buf(buffer, size);
#endif
}

#endif // N2N_RANDOM_H_