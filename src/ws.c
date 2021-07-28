#include <cwire/ws.h>
#include <cwire/url.h>
#include <cwire/b64.h>
#include <string.h>
#include <assert.h> 
#include <openssl/rand.h>
#include <openssl/err.h>

#include <cwire/no_malloc.h>

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

static
int cwr__ws_header_includes (const char *needle, cwr_buf_t *header) 
{
    size_t off = 0;
    int lws = 1;
    for (size_t i = 0; i < header->len; i++)
    {
        if (header->base[i] == ' ' || header->base[i] == '\t')
        {
            if (lws)
                off++;
            else 
                return -1;
            continue;
        }

        lws = 0;

        if (!token_chars[header->base[i]])
            return -1;

        if (header->base[i] == ',')
        {
            if (strncmp(needle, header->base + off, i - off))
                return 1;
            off = i + 1;
            lws = 1;
        }
    }
    return !strncmp(needle, header->base + off, header->len - off);
}

int cwr_ws_writer (cwr_ws_t *ws, const void *buf, size_t len) 
{
    return ws->stream->io.writer(ws->stream, buf, len);
}

int cwr_ws_reader (cwr_linkable_t *stream, const void *dat, size_t nbytes)
{
    cwr_ws_t *ws = (cwr_ws_t *)stream->io.child;


}

static 
int str2int(const char* str, int len)
{
    int i;
    int ret = 0;
    for(i = 0; i < len; ++i)
    {
        ret = ret * 10 + (str[i] - '0');
    }
    return ret;
}

static int cwr__ws_header_field (llhttp_t *ll, const char *at, size_t len) {
    cwr_ws_t *ws = ll->data;

    if (ws->header_field.base == NULL)
    {
        if (cwr_buf_malloc(&ws->header_field, ws->m_ctx, 1) == NULL)
        {
            ws->io.err_type = CWR_E_INTERNAL;
            ws->io.err_code = CWR_E_INTERNAL_OOM;
            if (ws->io.on_error)
                ws->io.on_error(ws);
            return 0;
        }
    }

    if (cwr_buf_push_back(&ws->header_field, at, len) == NULL)
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        if (ws->io.on_error)
            ws->io.on_error(ws);
    }

    return 0;
}

static int cwr__ws_header_value (llhttp_t *ll, const char *at, size_t len) {
    cwr_ws_t *ws = ll->data;

    if (ws->header_value.base == NULL)
    {
        if (cwr_buf_malloc(&ws->header_value, ws->m_ctx, 1) == NULL)
        {
oom:
            ws->io.err_type = CWR_E_INTERNAL;
            ws->io.err_code = CWR_E_INTERNAL_OOM;
            if (ws->io.on_error)
                ws->io.on_error(ws);
            return 0;
        }
    }

    if (cwr_buf_push_back(&ws->header_value, at, len) == NULL)
        goto oom;

    return 0;
}

static int cwr__ws_header_field_complete (llhttp_t *ll)
{
    cwr_ws_t *ws = ll->data;

    ws->header_field.len = 0;
    return 0;
} 

static int cwr__ws_header_value_complete (llhttp_t *ll)
{
    cwr_ws_t *ws = ll->data;

    ws->header_value.len = 0;
    return 0;
} 


int cwr_ws_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_ws_t *ws)
{
    memset(ws, 0, sizeof(cwr_ws_t));
    ws->m_ctx = m_ctx;

    ws->io.writer = cwr_ws_writer;

    ws->stream = stream;
    ws->stream->io.child = (cwr_linkable_t *)ws;
    ws->stream->io.reader = cwr_ws_reader;

    llhttp_settings_init(&ws->http_parser_settings);

    ws->http_parser_settings.on_header_field = cwr__ws_header_field;
    ws->http_parser_settings.on_header_value = cwr__ws_header_value;

    ws->http_parser_settings.on_header_field_complete = cwr__ws_header_field_complete;
    ws->http_parser_settings.on_header_value_complete = 
    cwr__ws_header_value_complete;

    memcpy(ws->key, CWR_WS_KEY, sizeof(CWR_WS_KEY));

    return 0;
}

static
int cwr__ws_handshake (cwr_ws_t *ws)
{
    cwr_buf_t buf;
    if (!cwr_buf_malloc(&buf, ws->m_ctx, 256))
    {
        cwr_free(ws->m_ctx, ws->host_name);
        cwr_free(ws->m_ctx, ws->resource_name);
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (!cwr_buf_push_back(&buf, "GET ", 4))
    {
oom_shake:
        cwr_free(ws->m_ctx, ws->host_name);
        cwr_free(ws->m_ctx, ws->resource_name);
        cwr_buf_free(&buf);
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (!cwr_buf_push_back(&buf, ws->resource_name, strlen(ws->resource_name)))
        goto oom_shake;
    
    if (!cwr_buf_push_back(&buf, " HTTP/1.1\r\n", 11))
        goto oom_shake;

    if (!cwr_buf_push_back(&buf, "Host: ", 6))
        goto oom_shake;

    if (!cwr_buf_push_back(&buf, ws->host_name, strlen(ws->host_name)))
        goto oom_shake;

    if (!cwr_buf_push_back(&buf, CWR_WS_HEADERS, sizeof(CWR_WS_HEADERS) - 1))
        goto oom_shake;
    
    /* Generate a nonce to use as the Sec-WebSocket-Key */
    char bytes[16];
    int r = RAND_bytes(bytes, 16);
    if (!r)
    {
err_ssl:
        cwr_free(ws->m_ctx, ws->host_name);
        cwr_free(ws->m_ctx, ws->resource_name);
        cwr_buf_free(&buf);
        ws->io.err_type = CWR_E_SSL_ERR;
        ws->io.err_code = ERR_get_error();
        return CWR_E_SSL_ERR;
    }
    
    cwr_base64_encode(bytes, 16, ws->key, 24, CWR_B64_MODE_NORMAL);
    
    if (!cwr_buf_push_back(&buf, "Sec-WebSocket-Key: ", 19))
        goto oom_shake;

    if (!cwr_buf_push_back(&buf, ws->key, 24))
        goto oom_shake;

    /* Add user defined subprotocols */
    if (ws->protocols != NULL)
    {
        if (!cwr_buf_push_back(&buf, "\r\nSec-WebSocket-Protocol: ", 26))
            goto oom_shake;

        size_t i = 0;
        char *cur = (char *)ws->protocols[i];
        while (cur != NULL)
        {
            while (cur[0] != '\0')
            {
                if (!token_chars[cur[0]])
                {
                    cwr_free(ws->m_ctx, ws->host_name);
                    cwr_free(ws->m_ctx, ws->resource_name);
                    cwr_buf_free(&buf);
                    ws->io.err_type = CWR_E_USER;
                    ws->io.err_code = CWR_E_USER_WS_PROTOCOL_VAL;
                    return CWR_E_USER_WS_PROTOCOL_VAL;
                }
                if (!cwr_buf_push_back(&buf, cur++, 1))
                    goto oom_shake;
            }
            cur = (char *)ws->protocols[++i];
            if (cur != NULL)
                if (!cwr_buf_push_back(&buf, ",", 1))
                    goto oom_shake;
        }
    }

    if (ws->handshake_headers != NULL)
    {
        size_t i = 0;
        char *cur = (char *)ws->handshake_headers[i];

        while (cur != NULL)
        {
            if (ws->handshake_headers[i + 1] == NULL)
                break;

            if (!cwr_buf_push_back(&buf, "\r\n", 2))
                goto oom_shake;
            
            while (cur[0] != '\0')
            {
                if (!token_chars[cur[0]])
                {
                    cwr_free(ws->m_ctx, ws->host_name);
                    cwr_free(ws->m_ctx, ws->resource_name);
                    cwr_buf_free(&buf);
                    ws->io.err_type = CWR_E_USER;
                    ws->io.err_code = CWR_E_USER_HTTP_FIELD;
                    return CWR_E_USER_HTTP_FIELD;
                }
                if (!cwr_buf_push_back(&buf, cur++, 1))
                    goto oom_shake;
            }
            cur = (char *)ws->handshake_headers[++i];

            if (!cwr_buf_push_back(&buf, ": ", 2))
                goto oom_shake;

            if (!cwr_buf_push_back(&buf, cur, strlen(cur)))
                goto oom_shake;
            cur = (char *)ws->handshake_headers[++i];
        }
    }

    if (!cwr_buf_push_back(&buf, "\r\n\r\n", 4))
        goto oom_shake;
/*
    r = ws->stream->io.writer(ws, buf.base, buf.len);
    if (r)
    {
        cwr_free(ws->m_ctx, ws->host_name);
        cwr_free(ws->m_ctx, ws->resource_name);
        cwr_buf_free(&buf);
        ws->io.err_type = CWR_E_UNDERLYING;
        ws->io.err_code = r;
        return r;
    } 

    ws->state = CWR_WS_CONNECTING;*/

    fwrite(buf.base, 1, buf.len, stdout);

    cwr_buf_free(&buf);

    /* Generate SHA1 Hash for later use */
    SHA_CTX sha1;

    r = SHA1_Init(&sha1);
    if (!r)
        goto err_ssl;

    r = SHA1_Update(&sha1, ws->key, sizeof(ws->key) - 1);
    if (!r)
        goto err_ssl;

    char digest[SHA_DIGEST_LENGTH];

    r = SHA1_Final(digest, &sha1);
    if (!r)
        goto err_ssl;

    cwr_base64_encode(digest, SHA_DIGEST_LENGTH, ws->key_hash, sizeof(ws->key_hash), CWR_B64_MODE_NORMAL);
    /* End SHA1 hash generation */

    return CWR_E_OK;
}

int cwr_ws_connect (cwr_ws_t *ws, const char* uri, size_t uri_len)
{
    assert(ws->host_name == NULL && "Host name is not null. Did you forget to call cwr_ws_init?");
    assert(ws->resource_name == NULL && "Resource name is not null. Did you forget to call cwr_ws_init?");

    /* Setup http as client to receive responses, not requests */
    llhttp_init(&ws->http_parser, HTTP_RESPONSE, &ws->http_parser_settings);

    ws->http_parser.data = ws;

    /* URI must be parsed for use in handshake */
    struct http_parser_url u;
    http_parser_url_init(&u);

    if (http_parser_parse_url(uri, uri_len, 0, &u))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_URLPARSE;
        return CWR_E_INTERNAL_URLPARSE;
    }

    /* Fragment identifiers MUST NOT be used in WS URIs */
    if (u.field_data[UF_FRAGMENT].len)
    {
        ws->io.err_type = CWR_E_USER;
        ws->io.err_code = CWR_E_USER_WS_FRAGMENT;
        return CWR_E_USER_WS_FRAGMENT;
    }

    int has_port = u.field_data[UF_PORT].len;
    int port = 0;
    ws->is_secure = 0;

    if (has_port)
        port = str2int(uri + u.field_data[UF_PORT].off, has_port);

    switch (u.field_data[UF_SCHEMA].len)
    {
    case 3:
        if (!strncasecmp(uri + u.field_data[UF_SCHEMA].off, "wss", u.field_data[UF_SCHEMA].len))
        {
            ws->is_secure = 1;
            if (!has_port)
                port = 443;
        }
        break;

    case 2:
        if (!strncasecmp(uri + u.field_data[UF_SCHEMA].off, "ws", u.field_data[UF_SCHEMA].len))
        {
            if (!has_port)
                port = 80;
        }
        break;
    
    default:
        {
            ws->io.err_type = CWR_E_USER;
            ws->io.err_code = CWR_E_USER_WS_INVALID_SCHEMA;
            return CWR_E_USER_WS_INVALID_SCHEMA;
        }
        break;
    }

    int is_default_port = (ws->is_secure && port == 443) || (!ws->is_secure && port == 80);

    /* Build the host_name */
    ws->host_name = cwr_mallocz(ws->m_ctx, 
        is_default_port ?
            u.field_data[UF_HOST].len + 1 /* \0 */ :
            u.field_data[UF_HOST].len + 1 /* : */ + u.field_data[UF_PORT].len + 1 /* \0 */);

    if (ws->host_name == NULL)
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    memcpy(ws->host_name, uri + u.field_data[UF_HOST].off, u.field_data[UF_HOST].len);
    if (!is_default_port)
    {
        ws->host_name[u.field_data[UF_HOST].len] = ':';
        memcpy(ws->host_name + u.field_data[UF_HOST].len + 1, uri + u.field_data[UF_PORT].off, u.field_data[UF_PORT].len);
    }

    int has_path = u.field_data[UF_PATH].len;
    int has_query = u.field_data[UF_QUERY].len;

    ws->resource_name = cwr_mallocz(ws->m_ctx, 
        (has_path ? u.field_data[UF_PATH].len : 1 /* / */) +
        (has_query ? 1 /* ? */ + u.field_data[UF_QUERY].len : 0) + 
        1 /* \0 */
    );

    if (ws->resource_name == NULL)
    {
        cwr_free(ws->m_ctx, ws->host_name);
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (has_path)
        memcpy(ws->resource_name, uri + u.field_data[UF_PATH].off, u.field_data[UF_PATH].len);
    else
        ws->resource_name[0] = '/';

    if (has_query)
    {
        ws->resource_name[has_path ? u.field_data[UF_PATH].len : 1] = '?';
        memcpy(ws->resource_name + (has_path ? u.field_data[UF_PATH].len : 1) + 1, 
               uri + u.field_data[UF_QUERY].off, 
               u.field_data[UF_QUERY].len);
    }

    return cwr__ws_handshake(ws);
}

int cwr_ws_send (cwr_ws_t *ws, const void *buf, size_t len);
int cwr_ws_shutdown (cwr_ws_t *ws);
void cwr_ws_free (cwr_ws_t *ws);