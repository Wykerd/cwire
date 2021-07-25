#include <cwire/tls.h>

#include <cwire/no_malloc.h>

static int cwr__tls_flush_wbio (cwr_tls_t *tls)
{
    char buf[CWR_SSL_IO_BUF_SIZE];
    int r = 0,
        wr = 0;
    ERR_clear_error();
    do
    {
        r = BIO_read(tls->wbio, buf, sizeof(buf));
        if (r > 0)
        {
            int wr = tls->io.writer(tls, buf, r);
            if (wr)
                return wr;
            if (tls->io.on_write)
            {
                wr = tls->io.on_write(tls, buf, r);
                if (wr)
                    return wr;
            }
        }
        else if (!BIO_should_retry(tls->wbio))
        {
            tls->io.err_type = CWR_E_SSL_BIO_IO;
            tls->io.err_code = ERR_get_error();
            return r;
        }
    } while (r > 0);

    return 0;
}

static int cwr__tls_flush_enc_buf(cwr_tls_t *tls)
{
    int r = 0,
        status;

    ERR_clear_error();
    while (tls->enc_buf.len > 0)
    {
        int r = SSL_write(tls->ssl, tls->enc_buf.base, tls->enc_buf.len);
        status = SSL_get_error(tls->ssl, r);

        if (r > 0)
        {
            /* consume bytes */
            cwr_buf_shift(&tls->enc_buf, r);

            r = cwr__tls_flush_wbio(tls);
            if (r)
                return r;
        }

        if (!((status == 0) || (status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ)))
            return 1;

        if (r == 0)
            break;
    }
    return 0;
}

int cwr__tls_handshake(cwr_tls_t *tls)
{
    int r = 0,
        wr = 0,
        status = 0;

    ERR_clear_error();
    if (!SSL_is_init_finished(tls->ssl))
    {
        r = SSL_do_handshake(tls->ssl);
        status = SSL_get_error(tls->ssl, r);
        if ((status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ))
        {
            r = cwr__tls_flush_wbio(tls);
            if (r)
                return r;
        }
    }
    return !((status == 0) || (status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ));
}

int cwr_tls_reader (cwr_linkable_t *sock, const void *dat, size_t nbytes)
{
    cwr_tls_t *tls = sock->io.child;
    char buf[CWR_SSL_IO_BUF_SIZE];
    int r = 0,
        status;
    size_t len = nbytes;
    char *src = (char *)dat;

    ERR_clear_error();

    while (len > 0)
    {
        r = BIO_write(tls->rbio, src, len);

        if (r <= 0)
        {
            tls->io.err_type = CWR_E_SSL_BIO_IO;
            tls->io.err_code = ERR_get_error();
            return r;
        }

        src += r;
        len -= r;

        if (!SSL_is_init_finished(tls->ssl))
        {
            int rr = cwr__tls_handshake(tls);
            if (rr)
                return rr;
            if (!SSL_is_init_finished(tls->ssl))
                return 0;
            else
            {
                rr = cwr__tls_flush_enc_buf(tls);
                if (rr)
                    return rr;
            }
        }

        do
        {
            r = SSL_read(tls->ssl, buf, sizeof(buf));
            if (r > 0)
            {
                int rr = tls->io.reader(tls, buf, (size_t)r);
                if (rr)
                    return rr;
                if (tls->io.on_read)
                {
                    rr = tls->io.on_read(tls, buf, (size_t)r);
                    if (rr)
                        return rr;
                }
            }
            else if (r < 0)
                break;
        } while (r > 0);

        if ((SSL_get_shutdown(tls->ssl) & SSL_RECEIVED_SHUTDOWN) || (SSL_get_shutdown(tls->ssl) & SSL_SENT_SHUTDOWN))
        {
            /* Shut down */
            if (tls->on_close)
                tls->on_close(tls);

            return 0;
        }

        /* Do we want some io? */
        status = SSL_get_error(tls->ssl, r);
        if ((status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ))
        {
            r = cwr__tls_flush_wbio(tls);
            if (r)
                return r;
        }

        if (!((status == 0) || (status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ)))
            return 1;
    }
    return 0;
}

int cwr_tls_writer (cwr_tls_t *tls, const void *buf, size_t len) 
{
    return tls->sock->io.writer(tls->sock, buf, len);
}

static int cwr__tls_init_intr(cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *sock, cwr_tls_t *tls)
{
    tls->m_ctx = m_ctx;

    tls->io.reader = NULL;
    tls->io.on_write = NULL;
    tls->io.on_read = NULL;
    tls->io.on_error = NULL;
    tls->io.writer = cwr_tls_writer;

    tls->sock = sock;
    tls->sock->io.reader = cwr_tls_reader;
    tls->sock->io.child = tls;

    if (!cwr_buf_malloc(&tls->enc_buf, tls->m_ctx, CWR_SSL_IO_BUF_SIZE))
    {
        tls->io.err_type = CWR_E_INTERNAL;
        tls->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    tls->ssl = SSL_new(tls->sec_ctx.ssl_ctx);

    tls->rbio = cwr_crypto_bio_new(tls->m_ctx);
    tls->wbio = cwr_crypto_bio_new(tls->m_ctx);
    SSL_set_bio(tls->ssl, tls->rbio, tls->wbio);
}

unsigned long cwr_tls_init_ex (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *sock, cwr_tls_t *tls, cwr_secure_ctx_t *sec_ctx)
{
    tls->sec_ctx = *sec_ctx;
    return cwr__tls_init_intr(m_ctx, sock, tls);
}

unsigned long cwr_tls_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *sock, cwr_tls_t *tls)
{
    unsigned long r;
    r = cwr_sec_ctx_init(&tls->sec_ctx, m_ctx, TLS_method(), 0, 0);
    if (r)
    {
ssl_err:
        tls->io.err_type = CWR_E_SSL_ERR;
        tls->io.err_code = r;
        return r;
    }
    r = cwr_sec_ctx_set_cipher_suites(&tls->sec_ctx, CWR_SSL_DEFAULT_CIPHER_SUITES);
    if (r)
        goto ssl_err;
    r = cwr_sec_ctx_set_ciphers(&tls->sec_ctx, CWR_SSL_DEFAULT_CIPHER_LISTS);
    if (r)
        goto ssl_err;
    r = cwr_sec_ctx_add_root_certs(&tls->sec_ctx);
    if (r)
        goto ssl_err;
    

    if (cwr__tls_init_intr(m_ctx, sock, tls))
        return 1;

    return r;
}

int cwr_tls_write(cwr_tls_t *tls, const void *buf, size_t len)
{
    cwr_buf_push_back(&tls->enc_buf, (char *)buf, len);

    if (!SSL_is_init_finished(tls->ssl))
        return 0;

    return cwr__tls_flush_enc_buf(tls);
}

int cwr_tls_connect(cwr_tls_t *tls)
{
    SSL_set_connect_state(tls->ssl);
    return cwr__tls_handshake(tls);
}

void cwr_tls_free(cwr_tls_t *tls)
{
    SSL_free(tls->ssl); /* This merhod also frees the BIOs */
    cwr_buf_free(&tls->enc_buf);
}

int cwr_tls_shutdown (cwr_tls_t *tls)
{
    ERR_clear_error();
    int r = SSL_shutdown(tls->ssl);
    int status = SSL_get_error(tls->ssl, r);
    if ((status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ))
    {
        r = cwr__tls_flush_wbio(tls);
        if (r)
            return r;
    }

    return !((status == 0) || (status == SSL_ERROR_WANT_WRITE) || (status == SSL_ERROR_WANT_READ));
}
