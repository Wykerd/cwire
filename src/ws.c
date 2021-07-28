#include <cwire/ws.h>
#include <cwire/url.h>
#include <cwire/b64.h>
#include <string.h>
#include <assert.h> 
#include <openssl/rand.h>
#include <openssl/err.h>
#if defined(__linux__)
#  include <endian.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(APPLE)
#  include <sys/endian.h>
#elif defined(__OpenBSD__)
#  include <sys/types.h>
#  define be16toh(x) betoh16(x)
#  define be32toh(x) betoh32(x)
#  define be64toh(x) betoh64(x)
#elif defined(_MSC_VER)
#  include <stdlib.h>
#  define be16toh(x) _byteswap_ushort(x)
#  define be32toh(x) _byteswap_ulong(x)
#  define be64toh(x) _byteswap_uint64(x)
#endif

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
int cwr__ws_header_includes (const char *needle, size_t needle_len, cwr_buf_t *header) 
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

        if (header->base[i] == ',')
        {
            if ((i - off == needle_len) && !strncasecmp(needle, header->base + off, i - off))
                return 1;
            off = i + 1;
            lws = 1;
            continue;
        }

        if (!token_chars[header->base[i]])
            return -1;
    }
    return (header->len - off == needle_len) && !strncasecmp(needle, header->base + off, header->len - off);
}

int cwr_ws_writer (cwr_ws_t *ws, const void *buf, size_t len) 
{
    return ws->stream->io.writer(ws->stream, buf, len);
}

static
void cwr__ws_fail_connection (cwr_ws_t *ws, uint16_t status_code)
{
    // TODO:
}

int cwr_ws_reader (cwr_linkable_t *stream, const void *dat, size_t nbytes)
{
    cwr_ws_t *ws = (cwr_ws_t *)stream->io.child;

    fwrite(dat, 1, nbytes, stdout);

    if (ws->state == CWR_WS_CONNECTING)
    {
        llhttp_errno_t err = llhttp_execute(&ws->http_parser, dat, nbytes);
        if (err != HPE_OK) {
            ws->io.err_type = CWR_E_LLHTTP;
            ws->io.err_code = err;
            if (ws->io.on_error)
                ws->io.on_error(ws);
            if (ws->on_fail)
                ws->on_fail(ws);
            ws->state = CWR_WS_FAILED;
        }

        return 0;
    }

    if (!cwr_buf_push_back(&ws->buffer, dat, nbytes)) 
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        if (ws->io.on_error)
            ws->io.on_error(ws);
        return 0;
    }

    char *off = ws->buffer.base;
    size_t len = ws->buffer.len;
new_state:
    if (len == 0)
        return 0;

    switch (ws->intr_state)
    {
    case CWR_WS_S_NEW:
        {
            char opcode = ((char *)off)[0] & ~0b11110000;
            // if (opcode == CWR_WS_OP_CONTINUATION) 
            ws->opcode = opcode;
            ws->fin = ((char *)off)[0] & (1 << 7);
            if (((char *)off)[0] & 0b01110000) // check if a reserved bit is set
            {
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_RESERVED_BIT_SET;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
            }
            ws->intr_state = CWR_WS_S_OP;
            off++;
            len--;
            goto new_state;
        }
        break;

    case CWR_WS_S_OP:
        {
            char payload_len = ((char *)off)[0] & ~(1 << 7);
            ws->mask = ((char *)off)[0] & (1 << 7);
            if (ws->client_mode && ws->mask)
            {
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_SERVER_MASKING;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
            }
            if (payload_len < 126)
            {
                ws->payload_len = payload_len;
                ws->intr_state = ws->mask ? CWR_WS_S_MASKING_KEY : CWR_WS_S_PAYLOAD;
            }
            else if (payload_len == 126)
                ws->intr_state = CWR_WS_S_LEN16;
            else if (payload_len == 127)
                ws->intr_state = CWR_WS_S_LEN64;

            off++;
            len--;
            goto new_state;
        }
        break;

    case CWR_WS_S_LEN16:
        {
            if (len < 2)
                goto consume_used;
            
            uint16_t payload_len = 0;
            memcpy(&payload_len, off, 2);
            ws->payload_len = be16toh(payload_len);
            ws->intr_state = ws->mask ? CWR_WS_S_MASKING_KEY : CWR_WS_S_PAYLOAD;
            off += 2;
            len -= 2;
            goto new_state;
        }
        break;
    
    case CWR_WS_S_LEN64:
        {
            if (len < 8)
                goto consume_used;

            uint64_t payload_len = 0;
            memcpy(&payload_len, off, 8);
            ws->payload_len = be64toh(payload_len);
            if (ws->payload_len & (uint64_t)(1ull << 63))
            {
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_PAYLOAD_LENGTH;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
            }
            ws->intr_state = ws->mask ? CWR_WS_S_MASKING_KEY : CWR_WS_S_PAYLOAD;
            off += 8;
            len -= 8;
            goto new_state;
        }
        break;

    case CWR_WS_S_MASKING_KEY:
        {
            if (len < 4)
                goto consume_used;

            uint32_t masking_key = 0;
            memcpy(&masking_key, off, 4);
            ws->masking_key = masking_key;
            ws->intr_state = CWR_WS_S_PAYLOAD;
            off += 4;
            len -= 4;
            goto new_state;
        }
        break;

    case CWR_WS_S_PAYLOAD:
        {
            if (len < ws->payload_len)
                goto consume_used;
            
            if (ws->on_message)
                ws->on_message(ws, off, ws->payload_len);
            
            if (ws->fin)
                ws->on_message_complete(ws);

            ws->intr_state = CWR_WS_S_NEW;
            off += ws->payload_len;
            len -= ws->payload_len;
            goto new_state;
        }
        break;

    default:
        assert(0 && "Unreachable code reached");
        break;
    }

consume_used:
    if (ws->buffer.len - len)
        cwr_buf_shift(&ws->buffer, ws->buffer.len - len);

    return 0;
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

static 
int cwr__ws_hsc_field (llhttp_t *ll, const char *at, size_t len) {
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

static 
int cwr__ws_hsc_value (llhttp_t *ll, const char *at, size_t len) {
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

int cwr_ws_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_ws_t *ws)
{
    memset(ws, 0, sizeof(cwr_ws_t));
    ws->m_ctx = m_ctx;

    ws->io.writer = cwr_ws_writer;

    ws->stream = stream;
    ws->stream->io.child = (cwr_linkable_t *)ws;
    ws->stream->io.reader = cwr_ws_reader;

    llhttp_settings_init(&ws->http_parser_settings);

    memcpy(ws->key, CWR_WS_KEY, sizeof(CWR_WS_KEY));

    if (!cwr_buf_malloc(&ws->buffer, m_ctx, 131))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

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
    if (unlikely(!r))
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

    r = ws->stream->io.writer(ws->stream, buf.base, buf.len);
    if (r)
    {
        cwr_free(ws->m_ctx, ws->host_name);
        cwr_free(ws->m_ctx, ws->resource_name);
        cwr_buf_free(&buf);
        ws->io.err_type = CWR_E_UNDERLYING;
        ws->io.err_code = r;
        return r;
    } 

    ws->state = CWR_WS_CONNECTING;

    fwrite(buf.base, 1, buf.len, stdout);

    cwr_buf_free(&buf);

    /* Generate SHA1 Hash for later use */
    SHA_CTX sha1;

    r = SHA1_Init(&sha1);
    if (unlikely(!r))
        goto err_ssl;

    r = SHA1_Update(&sha1, ws->key, sizeof(ws->key) - 1);
    if (unlikely(!r))
        goto err_ssl;

    char digest[SHA_DIGEST_LENGTH];

    r = SHA1_Final(digest, &sha1);
    if (unlikely(!r))
        goto err_ssl;

    cwr_base64_encode(digest, SHA_DIGEST_LENGTH, ws->key_hash, sizeof(ws->key_hash), CWR_B64_MODE_NORMAL);
    /* End SHA1 hash generation */

    return CWR_E_OK;
}

static
int cwr__ws_hsc_status (llhttp_t *ll)
{
    cwr_ws_t *ws = ll->data;

    switch (ll->status_code)
    {
    case 101:
        {
            ws->header_state = CWR_WS_H_STATUS_OK;
        }
        break;

    case 300:
    case 301:
    case 302:
    case 303:
    case 304:
    case 307:
        {
            ws->header_state = CWR_WS_H_WANT_REDIRECT; 
            ws->io.err_code = CWR_E_WS;
            ws->io.err_type = CWR_E_WS_REDIRECT;
        }
        break;
    
    default:
        {
            ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
            ws->io.err_code = CWR_E_WS;
            ws->io.err_type = CWR_E_WS_INVALID_STATUS;
        }
        break;
    }

    return 0;
}

static
int cwr__ws_hsc_value_complete (llhttp_t *ll)
{
    cwr_ws_t *ws = ll->data;

    if ((ws->header_state & CWR_WS_H_HANDSHAKE_ERR) ||
        (ws->header_state & CWR_WS_H_HAS_REDIRECT))
        goto cleanup;

    if (ws->header_state & CWR_WS_H_WANT_REDIRECT)
    {
        if ((ws->header_field.len == 8) && !strncasecmp(ws->header_field.base, "Location", ws->header_field.len))
        {
            if (ws->on_want_redirect)
                ws->on_want_redirect(ws, ws->header_value.base, ws->header_value.len);
            ws->header_state = CWR_WS_H_HAS_REDIRECT;
        }
        goto cleanup;
    }

    if (!(ws->header_state & CWR_WS_H_UPGRADE_OK) &&
        (ws->header_field.len == 7) && 
        !strncasecmp(ws->header_field.base, "Upgrade", ws->header_field.len))
    {
        if ((ws->header_value.len != 9) ||
            strncasecmp(ws->header_value.base, "websocket", 9))
        {
            ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
            ws->io.err_code = CWR_E_WS;
            ws->io.err_type = CWR_E_WS_INVALID_UPGRADE_HEADER;
            goto cleanup;
        }
        ws->header_state |= CWR_WS_H_UPGRADE_OK;
        goto cleanup;
    }

    if (!(ws->header_state & CWR_WS_H_CONNECTION_OK) &&
        (ws->header_field.len == 10) && 
        !strncasecmp(ws->header_field.base, "Connection", ws->header_field.len))
    {
        if (!cwr__ws_header_includes("Upgrade", 7, &ws->header_value))
        {
            ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
            ws->io.err_code = CWR_E_WS;
            ws->io.err_type = CWR_E_WS_INVALID_CONNECTION_HEADER;
            goto cleanup;
        }

        ws->header_state |= CWR_WS_H_CONNECTION_OK;
        goto cleanup;
    }

    if ((ws->protocols != NULL) &&
        (ws->protocol_selected == NULL) &&
        (ws->header_field.len == 22) && 
        !strncasecmp(ws->header_field.base, "Sec-WebSocket-Protocol", ws->header_field.len))
    {
        const char *prot = ws->protocols[0];
        while (prot != NULL)
        {
            size_t len = strlen(prot);
            if (len == ws->header_value.len && !memcmp(prot, ws->header_value.base, len))
            {
                ws->protocol_selected = cwr_mallocz(ws->m_ctx, ws->header_value.len + 1);
                if (!ws->protocol_selected)
                {
                    ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
                    ws->io.err_code = CWR_E_INTERNAL;
                    ws->io.err_type = CWR_E_INTERNAL_OOM;
                    goto cleanup;
                }
                memcpy(ws->protocol_selected, ws->header_value.base, ws->header_value.len);
                goto cleanup;
            }
        }
        ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
        ws->io.err_code = CWR_E_WS;
        ws->io.err_type = CWR_E_WS_INVALID_PROTOCOL;
        goto cleanup;
    }

    if (!(ws->header_state & CWR_WS_H_ACCEPT_OK) &&
        (ws->header_field.len == 20) && 
        !strncasecmp(ws->header_field.base, "Sec-WebSocket-Accept", ws->header_field.len))
    {
        if ((ws->header_value.len != sizeof(ws->key_hash)) || 
            memcmp(ws->header_value.base, ws->key_hash, sizeof(ws->key_hash)))
        {
            ws->header_state = CWR_WS_H_HANDSHAKE_ERR;   
            ws->io.err_code = CWR_E_WS;
            ws->io.err_type = CWR_E_WS_INVALID_SHA1_KEY;
            goto cleanup;
        }
        ws->header_state |= CWR_WS_H_ACCEPT_OK;
        goto cleanup;
    }

cleanup:
    ws->header_value.len = 0;
    ws->header_field.len = 0;

    return 0;
}

static
int cwr__ws_hsc_complete (llhttp_t *ll)
{
    cwr_ws_t *ws = ll->data;

    if (ws->header_state != CWR_WS_H_SUCCESSFUL)
    {
        if (ws->on_fail)
            ws->on_fail(ws);
        ws->state = CWR_WS_FAILED;
        goto cleanup;
    }
    ws->state = CWR_WS_OPEN;
    if (ws->on_open)
        ws->on_open(ws);
cleanup:
    cwr_buf_free(&ws->header_field);
    cwr_buf_free(&ws->header_value);
    return 0;
}

int cwr_ws_connect (cwr_ws_t *ws, const char* uri, size_t uri_len)
{
    assert(ws->host_name == NULL && "Host name is not null. Did you forget to call cwr_ws_init?");
    assert(ws->resource_name == NULL && "Resource name is not null. Did you forget to call cwr_ws_init?");

    /* Setup http as client to receive responses, not requests */
    llhttp_init(&ws->http_parser, HTTP_RESPONSE, &ws->http_parser_settings);

    ws->http_parser.data = ws;
    ws->http_parser_settings.on_status_complete = cwr__ws_hsc_status;
    ws->http_parser_settings.on_header_value = cwr__ws_hsc_value;
    ws->http_parser_settings.on_header_field = cwr__ws_hsc_field;
    ws->http_parser_settings.on_header_value_complete = cwr__ws_hsc_value_complete;
    ws->http_parser_settings.on_message_complete = cwr__ws_hsc_complete;

    ws->client_mode = 1;

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

int cwr_ws_send (cwr_ws_t *ws, const void *buf, size_t len, char opcode)
{

}

int cwr_ws_shutdown (cwr_ws_t *ws);
void cwr_ws_free (cwr_ws_t *ws);