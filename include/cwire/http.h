#ifndef CWR_HTTP_H
#define CWR_HTTP_H

#include "./common.h"
#include <llhttp.h>

typedef struct cwr_http_s cwr_http_t;

DEF_CWR_LINK_CLS(http_link, cwr_http_t);

typedef void (*cwr_http_cb)(cwr_http_t *);

struct cwr_http_s {
    void *data;
    cwr_http_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */
    cwr_linkable_t *stream; /* Underlying TCP/TLS implementation */

    llhttp_t parser;
    llhttp_settings_t parser_settings;

    const char *host;

    cwr_buf_t buffer;
};

int cwr_http_writer (cwr_http_t *ws, const char *buf, size_t len);

int cwr_http_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_http_t *http, enum llhttp_type type);

/**
 * @param body
 * When including a body, its up to the user to specify the appropriate
 * headers (content-length, content-type etc)
 * @param header
 * NULL terminated array of strings. 
 * Header fields and values are interleaved. 
 * For example: { "User-Agent", "cwire/0.0.0", "Origin", "http://example.com", NULL }
 */
int cwr_http_request (cwr_http_t *http, const char *method, const char *request_uri, const char **headers, const char *body, size_t body_len);
// TODO: int cwr_http_response (cwr_http_t *http);

int cwr_http_shutdown (cwr_http_t *http);

#endif