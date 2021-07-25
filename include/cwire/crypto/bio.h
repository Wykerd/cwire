#ifndef CWR_CRYPTO_BIO_H
#define CWR_CRYPTO_BIO_H
#include "../common.h"
#include <openssl/err.h>
#include <openssl/bio.h>

typedef struct cwr_crypto_buffer_s {
    char* base;
    size_t len;
    size_t max;
    void* opaque;
} cwr_crypto_buffer_t;

typedef struct cwr_crypto_bio_s {
    void *data;
    cwr_malloc_ctx_t *m_ctx;
    cwr_crypto_buffer_t *buf;
    cwr_crypto_buffer_t *readp;
    int eof_return;
} cwr_crypto_bio_t;

const BIO_METHOD* cwr_crypto_bio_get_method ();
BIO* cwr_crypto_bio_new (cwr_malloc_ctx_t *ctx);
BIO* cwr_crypto_bio_new_from_buf (cwr_malloc_ctx_t *ctx, const char *base, size_t len);
BIO* cwr_crypto_bio_new_from_buf_fixed (cwr_malloc_ctx_t *ctx, const char *base, size_t len);

#endif