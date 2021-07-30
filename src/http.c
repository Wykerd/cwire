#include <cwire/http.h>
#include <string.h>
#include <assert.h>

// 1*<any CHAR except CTLs or separators>
static const char token_chars[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1
};

int cwr_http_reader (cwr_linkable_t *stream, const char *dat, size_t nbytes)
{
    cwr_http_t *http = (cwr_http_t *)stream->io.child;
    llhttp_errno_t err = llhttp_execute(&http->parser, dat, nbytes);
    if (err != HPE_OK) {
        http->io.err_type = CWR_E_LLHTTP;
        http->io.err_code = err;
        if (http->io.on_error)
            http->io.on_error(http);
    }

    return 0;
}

int cwr_http_writer (cwr_http_t *ws, const char *buf, size_t len) 
{
    assert(0 && "Direct writing is not allowed");
    return 0;
}

int cwr_http_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_http_t *http, enum llhttp_type type)
{
    memset(http, 0, sizeof(cwr_http_t));
    llhttp_settings_init(&http->parser_settings);
    llhttp_init(&http->parser, HTTP_RESPONSE, &http->parser_settings);

    http->io.parent = stream;
    http->stream = stream;
    http->stream->io.child = (cwr_linkable_t *)http;
    http->stream->io.reader = cwr_http_reader;
    http->io.writer = cwr_http_writer;

    if (!cwr_buf_malloc(&http->buffer, m_ctx, 256))
    {
        http->io.err_type = CWR_E_INTERNAL;
        http->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    return 0;
}

int cwr_http_request (cwr_http_t *http, const char *method, const char *request_uri, const char **headers, const char *body, size_t body_len)
{
    if (!cwr_buf_push_back(&http->buffer, method, strlen(method)))
    {
oom:
        http->buffer.len = 0;
        http->io.err_type = CWR_E_INTERNAL;
        http->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (!cwr_buf_push_back(&http->buffer, " ", 1))
        goto oom;

    if (!cwr_buf_push_back(&http->buffer, request_uri, strlen(request_uri)))
        goto oom;

    if (!cwr_buf_push_back(&http->buffer, " HTTP/1.1\r\n", 11))
        goto oom;

    if (!cwr_buf_push_back(&http->buffer, "Host: ", 6))
        goto oom;

    if (!cwr_buf_push_back(&http->buffer, http->host, strlen(http->host)))
        goto oom;

    if (headers != NULL)
    {
        size_t i = 0;
        char *cur = (char *)headers[i];

        while (cur != NULL)
        {
            if (headers[i + 1] == NULL)
                break;

            if (!cwr_buf_push_back(&http->buffer, "\r\n", 2))
                goto oom;
            
            while (cur[0] != '\0')
            {
                if (!token_chars[cur[0]])
                {
                    http->buffer.len = 0;
                    http->io.err_type = CWR_E_USER;
                    http->io.err_code = CWR_E_USER_HTTP_FIELD;
                    return CWR_E_USER_HTTP_FIELD;
                }
                if (!cwr_buf_push_back(&http->buffer, cur++, 1))
                    goto oom;
            }
            cur = (char *)headers[++i];

            if (!cwr_buf_push_back(&http->buffer, ": ", 2))
                goto oom;

            if (!cwr_buf_push_back(&http->buffer, cur, strlen(cur)))
                goto oom;
            cur = (char *)headers[++i];
        }
    }

    if (!cwr_buf_push_back(&http->buffer, "\r\n\r\n", 4))
        goto oom;

    if (body)
        if (!cwr_buf_push_back(&http->buffer, body, body_len))
            goto oom;

    int r = http->stream->io.writer(http->stream, http->buffer.base, http->buffer.len);
    if (r)
    {
        http->buffer.len = 0;
        http->io.err_type = CWR_E_UNDERLYING;
        http->io.err_code = r;
        return r;
    } 

    http->buffer.len = 0;
    return 0;
}

int cwr_http_shutdown (cwr_http_t *http)
{
    if (http->buffer.base)
        cwr_buf_free(&http->buffer);
    return 0;
}