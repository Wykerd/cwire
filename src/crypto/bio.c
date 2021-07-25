#include <cwire/crypto/bio.h>
#include <string.h>

#define malloc(s) malloc_is_forbidden(s)
#define free(p) free_is_forbidden(p)
#define realloc(p,s) realloc_is_forbidden(p,s)
#define strdup(p) strdup_is_forbidden(s)

#define LIMIT_BEFORE_EXPANSION 0x5ffffffc

static int cwr__crypto_bio_create (BIO *bi) {
    BIO_set_shutdown(bi, 1);
    BIO_set_init(bi, 1);
    return 1;
}

static int cwr__crypto_bio_grow_clean (cwr_crypto_buffer_t *str, size_t len) {
    char *ret;
    size_t n;

    cwr_crypto_bio_t *m_bio = str->opaque;

    if (str->len >= len) {
        if (str->base != NULL)
            memset(&str->base[len], 0, str->len - len);
        str->len = len;
        return len;
    };

    if (str->max >= len) {
        memset(&str->base[str->len], 0, len - str->len);
        str->len = len;
        return len;
    }

    /* This limit is sufficient to ensure (len+3)/3*4 < 2**31 */
    if (len > LIMIT_BEFORE_EXPANSION)
        return 0;

    n = (len + 3) / 3 * 4;
    
    ret = cwr_realloc(m_bio->m_ctx, str->base, n);
    
    if (ret == NULL)
        return 0;
    
    str->base = ret;
    str->max = n;
    memset(&str->base[str->len], 0, len - str->len);
    str->len = len;

    return len;
}

static int cwr__crypto_bio_io_sync (BIO *b) {
    if (b != NULL && BIO_get_init(b) != 0 && BIO_get_data(b) != NULL) {
        cwr_crypto_bio_t *bbm = (cwr_crypto_bio_t *)BIO_get_data(b);

        if (bbm->readp->base != bbm->buf->base) {
            memmove(bbm->buf->base, bbm->readp->base, bbm->readp->len);
            bbm->buf->len = bbm->readp->len;
            bbm->readp->base = bbm->buf->base;
        }
    }
    return 0;
}

static int cwr__crypto_bio_write (BIO *b, const char *in, int inl) {
    int ret = -1;
    int blen;
    cwr_crypto_bio_t *bbm = (cwr_crypto_bio_t *)BIO_get_data(b);

    BIO_clear_retry_flags(b);

    if (in == NULL) {
        return ret;
    }
    
    if (inl == 0)
        return 0;

    blen = bbm->readp->len;
    cwr__crypto_bio_io_sync(b);
    
    if (cwr__crypto_bio_grow_clean(bbm->buf, blen + inl) == 0)
        return ret;

    memcpy(bbm->buf->base + blen, in, inl);
    *bbm->readp = *bbm->buf;
    ret = inl;

    return ret;
};

static int cwr__crypto_bio_puts (BIO *bp, const char *str) {
    int n, ret;

    n = strlen(str);
    ret = cwr__crypto_bio_write(bp, str, n);

    return ret;
}

static int cwr__crypto_bio_read (BIO *b, char *out, int outl) {
    int ret = -1;

    cwr_crypto_bio_t *bbm = (cwr_crypto_bio_t *)BIO_get_data(b);
    cwr_crypto_buffer_t *bm = bbm->readp;

    BIO_clear_retry_flags(b);
    ret = (outl >= 0 && (size_t)outl > bm->len) ? (int)bm->len : outl;

    if ((out != NULL) && (ret > 0)) {
        memcpy(out, bm->base, ret);
        bm->len -= ret;
        bm->max -= ret;
        bm->base += ret;
    } else if (bm->len == 0) {
        ret = bbm->eof_return;
        if (ret != 0)
            BIO_set_retry_read(b);
    }
    return ret;
};

static int cwr__crypto_bio_gets (BIO *bp, char *buf, int size) {
    int i, j;
    int ret = -1;
    char *p;
    cwr_crypto_bio_t *bbm = (cwr_crypto_bio_t *)BIO_get_data(bp);
    cwr_crypto_buffer_t *bm = bbm->readp;

    j = bm->len;
    if ((size - 1) < j)
        j = size - 1;
    if (j <= 0) {
        *buf = '\0';
        return 0;
    }
    p = bm->base;
    for (i = 0; i < j; i++) {
        if (p[i] == '\n') {
            i++;
            break;
        }
    }

    i = cwr__crypto_bio_read(bp, buf, i);
    if (i > 0)
        buf[i] = '\0';
    ret = i;
    return ret;
}

static int cwr__crypto_bio_buf_free (BIO *a) {
    if (a == NULL)
        return 0;

    if (BIO_get_shutdown(a) && BIO_get_init(a) && BIO_get_data(a) != NULL) {
        cwr_crypto_bio_t *bb = (cwr_crypto_bio_t *)BIO_get_data(a);
        cwr_crypto_buffer_t *b = bb->buf;
        
        if (b->base != NULL)
            cwr_free(bb->m_ctx, b->base);

        cwr_free(bb->m_ctx, b);
    }

    return 1;
}

static int cwr__crypto_bio_free (BIO *a) {
    cwr_crypto_bio_t *bb;

    if (a == NULL)
        return 0;

    bb = (cwr_crypto_bio_t *)BIO_get_data(a);
    if (bb == NULL)
        return 1;

    if (!cwr__crypto_bio_buf_free(a))
        return 0;

    cwr_free(bb->m_ctx, bb->readp);

    cwr_free(bb->m_ctx, bb);
    
    return 1;
}

static long cwr__crypto_bio_ctrl (BIO *b, int cmd, long num, void *ptr) {
    long ret = 1;
    char **pptr;
    cwr_crypto_bio_t *bbm = (cwr_crypto_bio_t *)BIO_get_data(b);
    cwr_crypto_buffer_t *bm, *bo;
    long off, remain;

    bm = bbm->readp;
    bo = bbm->buf;

    off = bm->base - bo->base;
    remain = bm->len;

    switch (cmd) {
    case BIO_CTRL_RESET:
        bm = bbm->buf;
        if (bm->base != NULL) {
            memset(bm->base, 0, bm->max);
            bm->len = 0;
            *bbm->readp = *bbm->buf;
        }
        break;
    case BIO_C_FILE_SEEK:
        if (num < 0 || num > off + remain)
            return -1;   /* Can't see outside of the current buffer */

        bm->base = bo->base + num;
        bm->len = bo->len - num;
        bm->max = bo->max - num;
        off = num;
        /* FALLTHRU */
    case BIO_C_FILE_TELL:
        ret = off;
        break;
    case BIO_CTRL_EOF:
        ret = (long)(bm->len == 0);
        break;
    case BIO_C_SET_BUF_MEM_EOF_RETURN:
        bbm->eof_return = (int)num;
        break;
    case BIO_CTRL_INFO:
        ret = (long)bm->len;
        if (ptr != NULL) {
            pptr = (char **)ptr;
            *pptr = (char *)&(bm->base[0]);
        }
        break;
    case BIO_C_SET_BUF_MEM:
        cwr__crypto_bio_free(b);
        BIO_set_shutdown(b, (int)num);
        bbm->buf = ptr;
        *bbm->readp = *bbm->buf;
        break;
    case BIO_C_GET_BUF_MEM_PTR:
        if (ptr != NULL) {
            cwr__crypto_bio_io_sync(b);
            bm = bbm->buf;
            pptr = (char **)ptr;
            *pptr = (char *)bm;
        }
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = (long)BIO_get_shutdown(b);
        break;
    case BIO_CTRL_SET_CLOSE:
        BIO_set_shutdown(b, (int)num);
        break;
    case BIO_CTRL_WPENDING:
        ret = 0L;
        break;
    case BIO_CTRL_PENDING:
        ret = (long)bm->len;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    default:
        ret = 0;
        break;
    }
    return ret;
};

const BIO_METHOD* cwr_crypto_bio_get_method () {
    static BIO_METHOD* method = NULL;

    if (method == NULL) {
        method = BIO_meth_new(BIO_TYPE_MEM, "CWire OpenSSL buffer");
        BIO_meth_set_create(method, cwr__crypto_bio_create);
        BIO_meth_set_write(method, cwr__crypto_bio_write);
        BIO_meth_set_read(method, cwr__crypto_bio_read);
        BIO_meth_set_puts(method, cwr__crypto_bio_puts);
        BIO_meth_set_gets(method, cwr__crypto_bio_gets);
        BIO_meth_set_ctrl(method, cwr__crypto_bio_ctrl);
        BIO_meth_set_destroy(method, cwr__crypto_bio_free);
        BIO_meth_set_callback_ctrl(method, NULL);
    };

    return method;
}

BIO* cwr_crypto_bio_new (cwr_malloc_ctx_t *ctx) {
    BIO* bi;
    bi = BIO_new(cwr_crypto_bio_get_method());
    if (bi == NULL) 
        return NULL;

    cwr_crypto_bio_t *m_bio = cwr_malloc(ctx, sizeof(cwr_crypto_bio_t));
    if (m_bio == NULL) {
        return NULL;
    };

    // Use parent context's malloc funcs
    m_bio->m_ctx = ctx;
    
    m_bio->buf = cwr_mallocz(m_bio->m_ctx, sizeof(*m_bio->buf));
    if (m_bio->buf == NULL) {
        cwr_free(ctx, m_bio);
        BIO_free(bi);
        return NULL;
    };

    m_bio->readp = cwr_mallocz(m_bio->m_ctx, sizeof(*m_bio->readp));
    if (m_bio->buf == NULL) {
        cwr_free(m_bio->m_ctx, m_bio->buf);
        cwr_free(ctx, m_bio);
        BIO_free(bi);
        return NULL;
    };

    *m_bio->readp = *m_bio->buf;

    m_bio->readp->opaque = m_bio;
    m_bio->buf->opaque = m_bio;

    m_bio->eof_return = -1;
    BIO_set_data(bi, m_bio);

    return bi;
};

BIO* cwr_crypto_bio_new_from_buf (cwr_malloc_ctx_t *ctx, const char *base, size_t len) {
    BIO* ptr;
    ptr = cwr_crypto_bio_new(ctx);
    
    if (ptr == NULL)
        return NULL;

    if (BIO_write(ptr, base, len) != len) {
        BIO_free(ptr);
        return NULL;
    };

    return ptr;
};

BIO* cwr_crypto_bio_new_from_buf_fixed (cwr_malloc_ctx_t *ctx, const char *base, size_t len) {
    BIO* ptr;
    ptr = cwr_crypto_bio_new_from_buf(ctx, base, len);

    if (ptr == NULL)
        return NULL;

    BIO_set_mem_eof_return(ptr, 0);

    return ptr;
}
