/* *
 * CWire's secure context is based off NodeJS's implimentation.
 * Thus, most of the functions below are adapted from NodeJS's source;
 * Available here: https://github.com/nodejs/node/blob/master/src/crypto/crypto_context.cc
 * */

#ifndef CWR_CRYPTO_CONTEXT_H
#define CWR_CRYPTO_CONTEXT_H
#include <cwire/common.h>
#include <cwire/crypto/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/kdf.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#define CWR_USE_OPENSSL_DEFAULT_STORE 0

typedef struct cwr_secure_ctx_s cwr_secure_ctx_t;

struct cwr_secure_ctx_s {
    cwr_malloc_ctx_t *m_ctx; 
    SSL_CTX *ssl_ctx; 
    void* data;
};


int cwr_crypto_no_password_cb (char* buf, int size, int rwflag, void* u) ;
int cwr_crypto_password_cb (char* buf, int size, int rwflag, void* u);

/* *
 * This function is pulled from stackoverflow
 * https://stackoverflow.com/questions/3810058/read-certificate-files-from-memory-instead-of-a-file-using-openssl
 * */
int cwr_sec_ctx_ssl_ctx_use_certificate_chain_bio (SSL_CTX* context, BIO* cbio);

X509_STORE* cwr_sec_ctx_new_root_cert_store (cwr_malloc_ctx_t *ctx, int use_openssl_default_store); // NewRootCertStore
unsigned long cwr_sec_ctx_set_key (cwr_secure_ctx_t *ctx, BIO *key, const uv_buf_t *password); // SetKey
unsigned long cwr_sec_ctx_set_cert (cwr_secure_ctx_t *ctx, BIO *cert); // SetCert
unsigned long cwr_sec_ctx_add_cacert (cwr_secure_ctx_t *ctx, BIO *bio); // AddCACert
unsigned long cwr_sec_ctx_add_crl (cwr_secure_ctx_t *ctx, BIO *bio); // AddCRL
int cwr_sec_ctx_add_root_certs (cwr_secure_ctx_t *ctx); // AddRootCerts
unsigned long cwr_sec_ctx_set_cipher_suites (cwr_secure_ctx_t *ctx, const char* ciphers); // SetCipherSuites
unsigned long cwr_sec_ctx_set_ciphers (cwr_secure_ctx_t *ctx, const char* ciphers); // SetCiphers
unsigned long cwr_sec_ctx_set_ecdh_curve (cwr_secure_ctx_t *ctx, const char* curve); // SetECDHCurve
unsigned long cwr_sec_ctx_set_sigalgs (cwr_secure_ctx_t *ctx, const char* sigalgs); // SetSigalgs

unsigned long cwr_sec_ctx_init (cwr_secure_ctx_t *ctx, cwr_malloc_ctx_t *m_ctx, const SSL_METHOD* method, int min_version, int max_version);
void cwr_sec_ctx_free (cwr_secure_ctx_t *ctx);

/** TODO: NOT YET IMPLEMENTED
 * LoadPKCS12
 * SetDHParam
 * GetTicketKeys
 * SetTicketKeys
 * SetSessionIdContext
 * */

#endif