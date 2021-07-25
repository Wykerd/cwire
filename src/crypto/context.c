#include "cwire/crypto/context.h"
#include "cwire/crypto/bio.h"
#include <string.h>

#include <cwire/no_malloc.h>

int cwr_crypto_no_password_cb (char* buf, int size, int rwflag, void* u) {
    return 0;
}

int cwr_crypto_password_cb (char* buf, int size, int rwflag, void* u) {
    const uv_buf_t* passphrase = u;

    if (passphrase != NULL) {
        size_t buflen = size;
        size_t len = passphrase->len;

        if (buflen < len)
            return -1;

        memcpy(buf, passphrase->base, len);
        return len;
    };

    return -1;
};

static const char* const root_certs[] = {
#include "cwire/crypto/root_certs.h"
};

#define root_certs_len (sizeof(root_certs) / sizeof(char*))

static X509_STORE* root_cert_store = NULL;

static X509* root_certs_vector[root_certs_len] = { NULL };

static int root_certs_loaded = 0;

unsigned long cwr_sec_ctx_ssl_ctx_use_certificate_chain_bio (SSL_CTX* context, BIO* cbio) {
    ERR_clear_error();

    X509_INFO *itmp;
    int i, count = 0, type = X509_FILETYPE_PEM;
    STACK_OF(X509_INFO) *inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if (!inf) {
        return 0;
    }

    /* Iterate over contents of the PEM buffer, and add certs. */
    int first = 1;
    for (i = 0; i < sk_X509_INFO_num(inf); i++) {
        itmp = sk_X509_INFO_value(inf, i);
        if (itmp->x509) {
            /* First cert is server cert. Remaining, if any, are intermediate certs. */
            if (first) {
                first = 0;

                /*
                 * Set server certificate. Note that this operation increments the
                 * reference count, which means that it is okay for cleanup to free it.
                 */
                if (!SSL_CTX_use_certificate(context, itmp->x509))
                    goto error;

                if (ERR_peek_error() != 0)
                    goto error;

                /* Get ready to store intermediate certs, if any. */
                SSL_CTX_clear_chain_certs(context);
            } else {
                /* Add intermediate cert to chain. */
                if (!SSL_CTX_add0_chain_cert(context, itmp->x509))
                    goto error;

                /*
                 * Above function doesn't increment cert reference count. NULL the info
                 * reference to it in order to prevent it from being freed during cleanup.
                 */
                itmp->x509 = NULL;
            }
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);

    return 0;

error:
    sk_X509_INFO_pop_free(inf, X509_INFO_free);

    return ERR_get_error();
}

X509_STORE* cwr_sec_ctx_new_root_cert_store (cwr_malloc_ctx_t *ctx, int use_openssl_default_store) {
    X509_STORE* store = X509_STORE_new();
    if (unlikely(!store)) {
        return NULL;
    }

    if (use_openssl_default_store) {
        X509_STORE_set_default_paths(store);
    } else {
        if (!root_certs_loaded) {
            for (size_t i = 0; i < root_certs_len; i++) {
                BIO* inbio = cwr_crypto_bio_new_from_buf_fixed(ctx, root_certs[i], strlen(root_certs[i]));
                if (!inbio)
                {
                    X509_STORE_free(store);
                    return NULL;
                }
                
                X509* x509 = PEM_read_bio_X509(inbio, NULL, cwr_crypto_no_password_cb, NULL);
                BIO_free(inbio);

                if (unlikely(x509 == NULL)) 
                {
                    X509_STORE_free(store);
                    return NULL;
                }

                root_certs_vector[i] = x509;
            };
        };

        for (size_t i = 0; i < root_certs_len; i++) {
            X509 *cert = root_certs_vector[i];
            X509_up_ref(cert);
            X509_STORE_add_cert(store, cert);
        };
    }

    return store;
};

cwr_intr_err_t cwr_sec_ctx_add_root_certs (cwr_secure_ctx_t *ctx) {
    if (root_cert_store == NULL) {
        root_cert_store = cwr_sec_ctx_new_root_cert_store(ctx->m_ctx, CWR_USE_OPENSSL_DEFAULT_STORE);
    };

    if (root_cert_store == NULL)
        return CWR_E_INTERNAL_OOM; 

    X509_STORE_up_ref(root_cert_store);
    SSL_CTX_set_cert_store(ctx->ssl_ctx, root_cert_store);

    return CWR_E_INTERNAL_OK;
};

unsigned long cwr_sec_ctx_set_key (cwr_secure_ctx_t *ctx, BIO *key, const uv_buf_t *password) 
{
    ERR_clear_error();

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(
        key,
        NULL,
        cwr_crypto_password_cb,
        (void *)password
    );

    if (!pkey) {
        return ERR_get_error();
    };

    int r = SSL_CTX_use_PrivateKey(ctx->ssl_ctx, pkey);

    if (!r) {
        EVP_PKEY_free(pkey);
        return ERR_get_error();
    }

    EVP_PKEY_free(pkey);

    return 0;
}

unsigned long cwr_sec_ctx_set_cert (cwr_secure_ctx_t *ctx, BIO *cert) {
    int r = cwr_sec_ctx_ssl_ctx_use_certificate_chain_bio(ctx->ssl_ctx, cert);
    if (r) 
        return r;

    return 0;
}

unsigned long cwr_sec_ctx_add_cacert (cwr_secure_ctx_t *ctx, BIO *bio) {
    X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx->ssl_ctx);

    X509* x509;
    while (x509 = PEM_read_bio_X509_AUX(bio, NULL, cwr_crypto_no_password_cb, NULL)) {
        if (cert_store == root_cert_store) {
            cert_store = cwr_sec_ctx_new_root_cert_store(ctx->m_ctx, CWR_USE_OPENSSL_DEFAULT_STORE);
            if (cert_store == NULL)
                return ERR_get_error();
            SSL_CTX_set_cert_store(ctx->ssl_ctx, cert_store);
        };
        X509_STORE_add_cert(cert_store, x509);
        SSL_CTX_add_client_CA(ctx->ssl_ctx, x509);
        X509_free(x509);
    }

    return 0;
};

unsigned long cwr_sec_ctx_add_crl (cwr_secure_ctx_t *ctx, BIO *bio) {
    X509_CRL *crl = PEM_read_bio_X509_CRL(bio, NULL, cwr_crypto_no_password_cb, NULL);

    if (!crl) {
        X509_CRL_free(crl);
        return ERR_get_error();
    };

    X509_STORE* cert_store = SSL_CTX_get_cert_store(ctx->ssl_ctx);

    if (cert_store == root_cert_store) {
        cert_store = cwr_sec_ctx_new_root_cert_store(ctx->m_ctx, CWR_USE_OPENSSL_DEFAULT_STORE);
        if (cert_store == NULL)
            return ERR_get_error();
        SSL_CTX_set_cert_store(ctx->ssl_ctx, cert_store);
    };

    X509_STORE_add_crl(cert_store, crl);
    X509_STORE_set_flags(
        cert_store,
        X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL
    );

    X509_CRL_free(crl);
    return 0;
};

unsigned long cwr_sec_ctx_set_cipher_suites (cwr_secure_ctx_t *ctx, const char* ciphers) {
    ERR_clear_error();
    
    if (!SSL_CTX_set_ciphersuites(ctx->ssl_ctx, ciphers)) {
        return ERR_get_error();
    };

    return 0;
};

unsigned long cwr_sec_ctx_set_ciphers (cwr_secure_ctx_t *ctx, const char* ciphers) {
    ERR_clear_error();

    if (!SSL_CTX_set_cipher_list(ctx->ssl_ctx, ciphers)) {
        unsigned long err = ERR_get_error();

        if (strlen(ciphers) == 0 && ERR_GET_REASON(err) == SSL_R_NO_CIPHER_MATCH) {
            return 0;
        };

        return err;
    }

    return 0;
};

unsigned long cwr_sec_ctx_set_ecdh_curve (cwr_secure_ctx_t *ctx, const char* curve) {
    if (strcmp(curve, "auto") == 0)
        return 0;

    if (!SSL_CTX_set1_curves_list(ctx->ssl_ctx, curve))
        return ERR_get_error();

    return 0;
};

unsigned long cwr_sec_ctx_set_sigalgs (cwr_secure_ctx_t *ctx, const char* sigalgs) {
    ERR_clear_error();
    int rv = SSL_CTX_set1_sigalgs_list(ctx->ssl_ctx, sigalgs);
    if (rv == 0) 
        return ERR_get_error();
    
    return 0;
}

void cwr_sec_ctx_free (cwr_secure_ctx_t *ctx) {
    SSL_CTX_free(ctx->ssl_ctx);
}

// min -> TLS1_VERSION // max -> 
unsigned long cwr_sec_ctx_init  (cwr_secure_ctx_t *ctx, cwr_malloc_ctx_t *m_ctx, const SSL_METHOD* method, int min_version, int max_version)
{
    ctx->m_ctx = m_ctx;
    ctx->ssl_ctx = SSL_CTX_new(method);
    if (!ctx->ssl_ctx)
        return ERR_get_error();

    SSL_CTX_set_app_data(ctx->ssl_ctx, ctx);

    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_options(ctx->ssl_ctx, SSL_OP_NO_SSLv3);

    SSL_CTX_clear_mode(ctx->ssl_ctx, SSL_MODE_NO_AUTO_CHAIN);
    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_session_cache_mode(ctx->ssl_ctx,
                                   SSL_SESS_CACHE_CLIENT |
                                   SSL_SESS_CACHE_SERVER |
                                   SSL_SESS_CACHE_NO_INTERNAL |
                                   SSL_SESS_CACHE_NO_AUTO_CLEAR);

    if (min_version) 
        SSL_CTX_set_min_proto_version(ctx->ssl_ctx, min_version);
    if (max_version)
        SSL_CTX_set_max_proto_version(ctx->ssl_ctx, max_version);

    return 0;
};
