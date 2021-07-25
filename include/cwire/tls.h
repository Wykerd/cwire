#ifndef CWR_TLS_H
#define CWR_TLS_H

#include "./common.h"
#include "./socket.h"
#include "./crypto/bio.h"
#include "./crypto/context.h"

typedef struct cwr_tls_s cwr_tls_t;

DEF_CWR_LINK_CLS(tls_link, cwr_tls_t);

typedef void (*cwr_tls_cb)(cwr_tls_t *);

struct cwr_tls_s {
    void *data;
    cwr_tls_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */
    uv_loop_t *loop; /* Event loop used */

    cwr_sock_t *sock;
    cwr_secure_ctx_t sec_ctx;
    SSL *ssl;

    /* Queue of unencrypted write data */
    cwr_buf_t enc_buf;

    BIO *rbio; /* SSL read buffer */
    BIO *wbio; /* SSL write buffer */
};

int cwr_tls_writer (cwr_tls_t *tls, const void *buf, size_t len);
unsigned long cwr_tls_init_ex (cwr_malloc_ctx_t *m_ctx, uv_loop_t *loop, cwr_sock_t *sock, cwr_tls_t *tls, cwr_secure_ctx_t *sec_ctx);
unsigned long cwr_tls_init (cwr_malloc_ctx_t *m_ctx, uv_loop_t *loop, cwr_sock_t *sock, cwr_tls_t *tls);
int cwr_tls_write (cwr_tls_t *tls, const void *buf, size_t len);
int cwr_tls_connect (cwr_tls_t *tls); 
/**
 * Notice: This method doesn't free the secure context, as it is reusable,
 * If you're not going to use it further you MUST call `cwr_sec_ctx_free`
 * before or after.
 */
void cwr_tls_free (cwr_tls_t *tls);

#endif