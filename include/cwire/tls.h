#ifndef CWR_TLS_H
#define CWR_TLS_H

#include "./common.h"
#include "./socket.h"
#include "./crypto/bio.h"
#include "./crypto/context.h"

#define CWR_SSL_IO_BUF_SIZE 1024
#define CWR_SSL_DEFAULT_CIPHER_SUITES "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
#define CWR_SSL_DEFAULT_CIPHER_LISTS "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA"

typedef struct cwr_tls_s cwr_tls_t;

DEF_CWR_LINK_CLS(tls_link, cwr_tls_t);

typedef void (*cwr_tls_cb)(cwr_tls_t *);

struct cwr_tls_s {
    void *data; /* Opaque data */
    cwr_tls_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */
    cwr_tls_cb on_close; /* SSL has closed */

    cwr_linkable_t *sock; /* Underlying tcp socket */
    cwr_secure_ctx_t sec_ctx; /* SSL secure context */
    SSL *ssl; /* SSL state machine */

    BIO *rbio; /* SSL read buffer */
    BIO *wbio; /* SSL write buffer */
    cwr_buf_t enc_buf; /* Queue of unencrypted write data */
};

int cwr_tls_reader (cwr_linkable_t *sock, const char *dat, size_t nbytes);
int cwr_tls_writer (cwr_tls_t *tls, const char *buf, size_t len);
unsigned long cwr_tls_init_ex (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *sock, cwr_tls_t *tls, cwr_secure_ctx_t *sec_ctx);
unsigned long cwr_tls_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *sock, cwr_tls_t *tls);
int cwr_tls_write (cwr_tls_t *tls, const void *buf, size_t len);
int cwr_tls_connect (cwr_tls_t *tls);
int cwr_tls_accept (cwr_tls_t *tls);
int cwr_tls_connect_with_sni (cwr_tls_t *tls, const char *host);
int cwr_tls_shutdown (cwr_tls_t *tls);
/**
 * Notice: This method doesn't free the secure context, as it is reusable,
 * If you're not going to use it further you MUST call `cwr_sec_ctx_free`
 * before or after.
 */
void cwr_tls_free (cwr_tls_t *tls);

#endif