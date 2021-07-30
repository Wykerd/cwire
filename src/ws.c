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
#  define htobe16(x) htobe16(x)
#  define htobe32(x) htobe32(x)
#  define htobe64(x) htobe64(x)
#elif defined(_MSC_VER)
#  include <stdlib.h>
#  define be16toh(x) _byteswap_ushort(x)
#  define be32toh(x) _byteswap_ulong(x)
#  define be64toh(x) _byteswap_uint64(x)
#  define htobe16(x) _byteswap_ushort(x)
#  define htobe32(x) _byteswap_ulong(x)
#  define htobe64(x) _byteswap_uint64(x)
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

int cwr_ws_writer (cwr_ws_t *ws, const char *buf, size_t len) 
{
    return ws->stream->io.writer(ws->stream, buf, len);
}

static inline
void cwr__ws_fail_connection (cwr_ws_t *ws, uint16_t status_code)
{
    int r = cwr_ws_close(ws, status_code);
    if (r)
    {
        // just force close if fail
        ws->state = CWR_WS_CLOSED;
        if (ws->on_close)
            ws->on_close(ws);
    }
}

static
void cwr__ws_mask (uint8_t mask[4], uint8_t *payload, size_t len)
{
    size_t new_len = len;
    uint32_t *mask_fast = (uint32_t *)mask;
    size_t i = 0;
    while (new_len >= 4)
    {
        uint32_t *chunk = (uint32_t *)&payload[i];
        *chunk ^= *mask_fast;
        new_len -= 4;
        i += 4;
    }
    
    for (int x = 0; x < new_len; x++)
    {
        payload[i + x] ^= mask[x % 4];
    }
}

static inline
size_t cwr__ws_write_header (cwr_ws_t *ws, uint8_t opcode, char *frame, size_t len, int fin)
{
    int off = 1;
    if (fin)
        frame[0] |= (1 << 7);
    frame[0] |= opcode;
    if (len < 126)
    {
        frame[1] |= len;
        off = 2;
    }
    else if (len <= 0xffff)
    {
        frame[1] |= 126;
        uint16_t r_len = len;
        r_len = htobe16(r_len);
        memcpy(&frame[2], &r_len, 2);
        off = 4;
    }
    else 
    {
        frame[1] |= 127;
        uint64_t r_len = len;
        r_len = htobe64(r_len);
        memcpy(&frame[2], &r_len, 8);
        off = 10;
    }
    if (ws->client_mode)
    {
        frame[1] |= (1 << 7);
        int r = RAND_bytes(&frame[off], 4);
        if (unlikely(!r))
            *((uint32_t *)&frame[off]) = rand(); // fallback to stdlib rand
        off += 4;
    }
    return off;
}

/* Immediately write the frame - skipping the write queue */
static inline
void cwr__ws_send_short_noq (cwr_ws_t *ws, uint8_t opcode, const void *data, uint8_t len)
{
    char frame[131] = { 0 };
    size_t data_idx = cwr__ws_write_header(ws, opcode, frame, len, 1);
    memcpy(&frame[data_idx], data, len);
    if (ws->client_mode)
        cwr__ws_mask(&frame[data_idx - 4], &frame[data_idx], len);

    int r = ws->stream->io.writer(ws->stream, frame, (ws->client_mode ? 6 : 2) + len);
    if (r)
    {
        ws->io.err_type = CWR_E_UNDERLYING;
        ws->io.err_type = CWR_E_USER_WRITER_ERROR;
        if (ws->io.on_error)
            ws->io.on_error(ws);
    }
}

static inline
void cwr__ws_handle_message (cwr_ws_t *ws, char *off)
{
    if (ws->mask)
        cwr__ws_mask(ws->masking_key, (uint8_t *)off, ws->payload_len);

    switch (ws->opcode)
    {
    case CWR_WS_OP_CONTINUATION:
    case CWR_WS_OP_TEXT: // TODO: utf-8 validation
    case CWR_WS_OP_BINARY:
        {
            if (ws->on_message && (ws->payload_len > 0))
                ws->on_message(ws, off, ws->payload_len);
            
            if (ws->fin)
                if (ws->on_message_complete)
                    ws->on_message_complete(ws);
        }
        break;
        
    case CWR_WS_OP_CLOSE:
        {
            uint16_t net_status = 0, status = 0;
            if (ws->payload_len >= 2)
            {
                memcpy(&net_status, off, 2);
                status = be16toh(net_status);
                if (ws->on_receive_close)
                    ws->on_receive_close(ws, status, off + 2, ws->payload_len - 2);
            }
            else if (ws->on_receive_close)
                ws->on_receive_close(ws, 0, NULL, 0);

            /* We've already sent a close frame */
            if (ws->state == CWR_WS_CLOSING)
            {
                /* Close handshake is done */
                ws->state = CWR_WS_CLOSED;
                if (ws->on_close)
                    ws->on_close(ws);
            }
            else /* close handshake response */
            {
                ws->state = CWR_WS_CLOSING;
                /* Send a close frame */
                if (net_status)
                    cwr__ws_send_short_noq(ws, CWR_WS_OP_CLOSE, &net_status, 2);
                else 
                    cwr__ws_send_short_noq(ws, CWR_WS_OP_CLOSE, NULL, 0);
            }
        }
        break;
        
    case CWR_WS_OP_PING:
        {
            cwr__ws_send_short_noq(ws, CWR_WS_OP_PONG, off, ws->payload_len);
        }
        break;
        
    case CWR_WS_OP_PONG:
        {
            /* We don't respond to a pong */
            if (ws->on_pong)
                ws->on_pong(ws, off, ws->payload_len);
        }
        break;
    
    default:
        {
            ws->io.err_type = CWR_E_WS;
            ws->io.err_code = CWR_E_WS_UNKNOWN_OPCODE;
            cwr__ws_fail_connection(ws, CWR_WS_STATUS_UNEXCEPTABLE_DATA);
        }
        break;
    }
}

int cwr_ws_reader (cwr_linkable_t *stream, const char *dat, size_t nbytes)
{
    cwr_ws_t *ws = (cwr_ws_t *)stream->io.child;

    if (ws->state == CWR_WS_CONNECTING)
    {
        llhttp_errno_t err = llhttp_execute(&ws->http_parser, dat, nbytes);
        if (err != HPE_OK) {
            if (err == HPE_PAUSED_UPGRADE)
                return 0;
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

    if ((ws->state == CWR_WS_CLOSED) || 
        (ws->state == CWR_WS_FAILED))
        return 0;

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
    switch (ws->intr_state)
    {
    case CWR_WS_S_NEW:
        {
            if (len == 0)
                goto consume_used;
            uint8_t opcode = ((uint8_t *)off)[0] & ~0b11110000;

            /* if fragmented and data frame is received */
            if (ws->is_fragmented && !(opcode & 0b1000) && (opcode != CWR_WS_OP_CONTINUATION))
            {
                /**
                 * The fragments of one message MUST NOT be interleaved between the
                 * fragments of another message
                 * See https://www.rfc-editor.org/rfc/rfc6455.html#page-35
                 */
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_INTERLEAVED_FRAGMENT;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
            }

            /* We're not currently receiving a fragmented message but received a continuation */
            if (!ws->is_fragmented && (opcode == CWR_WS_OP_CONTINUATION))
            {
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_CONTINUATION_UNFRAGMENTED;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
            }

            uint8_t fin = ((uint8_t *)off)[0] & (1 << 7);

            /* We're starting a new fragmented message */
            if (ws->fin && !fin)
            {
                if (!(opcode & 0b1000)) /* data frame */
                {
                    /* This will happen if a control frame was in the middle of a fragment */
                    if (opcode != CWR_WS_OP_CONTINUATION) 
                    {
                        ws->opcode_cont = opcode;
                        ws->is_fragmented = 1;
                    }
                }
                else /* control frames cannot be fragmented */
                {
                    ws->io.err_type = CWR_E_WS;
                    ws->io.err_code = CWR_E_WS_FRAGMENTED_CONTROL;
                    cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                    return 0;
                }
            }

            /* End of fragmented message */
            if (fin && (opcode == CWR_WS_OP_CONTINUATION))
            {
                ws->is_fragmented = 0;
            }

            ws->fin = fin;
            ws->opcode = opcode;
            if (((uint8_t *)off)[0] & 0b01110000) // check if a reserved bit is set
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
            if (len == 0)
                goto consume_used;
            uint8_t payload_len = ((uint8_t *)off)[0] & ~(1 << 7);
            ws->mask = ((uint8_t *)off)[0] & (1 << 7);
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
            else if ((payload_len > 125) && (ws->opcode & 0b1000))
            {
                ws->io.err_type = CWR_E_WS;
                ws->io.err_code = CWR_E_WS_CONTROL_FRAME_LEN;
                cwr__ws_fail_connection(ws, CWR_WS_STATUS_PROTOCOL_ERROR);
                return 0;
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

            memcpy(ws->masking_key, off, 4);
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
            
            cwr__ws_handle_message(ws, off);

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

static 
void cwr__ws_written (cwr_linkable_t *stream)
{
    cwr_ws_t *ws = (cwr_ws_t *)stream->io.child;
    if (!cwr_linkable_has_pending_write(stream))
    {
        switch (ws->state)
        {
        /* we can now write the next frame */
        case CWR_WS_CLOSING:
            {
                /* We just wrote the close frame */
                if (!ws->requested_close)
                {
                    ws->state = CWR_WS_CLOSED;
                    if (ws->on_close)
                        ws->on_close(ws);
                    break;
                }
            }
        case CWR_WS_OPEN: 
            {
                if (ws->write_queue_len.len)
                {
                    size_t *len = (size_t *)ws->write_queue_len.base;
                    int r = stream->io.writer(stream, ws->write_queue.base, *len);
                    cwr_buf_shift(&ws->write_queue, *len);
                    cwr_buf_shift(&ws->write_queue_len, sizeof(size_t));
                    if (r)
                    {
                        ws->io.err_type = CWR_E_UNDERLYING;
                        ws->io.err_type = CWR_E_USER_WRITER_ERROR;
                        if (ws->io.on_error)
                            ws->io.on_error(ws);
                    }
                }
            }
            break;
        
        default:
            break;
        }
    }
}

int cwr_ws_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_ws_t *ws)
{
    memset(ws, 0, sizeof(cwr_ws_t));
    ws->m_ctx = m_ctx;

    ws->io.writer = cwr_ws_writer;
    ws->io.parent = stream;

    ws->stream = stream;
    ws->stream->io.child = (cwr_linkable_t *)ws;
    ws->stream->io.reader = cwr_ws_reader;
    ws->stream->io.on_write = cwr__ws_written;

    ws->fin = 1;

    llhttp_settings_init(&ws->http_parser_settings);

    memcpy(ws->key, CWR_WS_KEY, sizeof(CWR_WS_KEY));

    if (!cwr_buf_malloc(&ws->buffer, m_ctx, 131))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (!cwr_buf_malloc(&ws->write_queue, m_ctx, 131))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    if (!cwr_buf_malloc(&ws->write_queue_len, m_ctx, sizeof(size_t)))
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

int cwr_ws_ping (cwr_ws_t *ws, const char *data, uint8_t len)
{
    if (ws->state != CWR_WS_OPEN)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_W_WS_NOT_OPEN;
        return CWR_W_WS_NOT_OPEN;
    }
    if (len > 125)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_E_WS_CONTROL_FRAME_LEN;
        return CWR_E_WS_CONTROL_FRAME_LEN;
    }
    cwr__ws_send_short_noq(ws, CWR_WS_OP_PING, data, len);
    return CWR_E_WS_OK;
}

int cwr_ws_send2 (cwr_ws_t *ws, const char *data, size_t len, uint8_t opcode, int fin)
{
    if (ws->state != CWR_WS_OPEN)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_W_WS_NOT_OPEN;
        return CWR_W_WS_NOT_OPEN;
    }
    /* Data is too big, we must split it */
    if (len & (uint64_t)(1ull << 63)) 
    {
        int r;
        r = cwr_ws_send2(ws, data, CWR_WS_MAX_PAYLOAD, opcode, 0);
        if (r)
            return r;
        r = cwr_ws_send2(ws, data + CWR_WS_MAX_PAYLOAD, len - CWR_WS_MAX_PAYLOAD, CWR_WS_OP_CONTINUATION, 1);
        if (r)
            return r;
        return CWR_E_WS_OK;
    }
    
    char frame[14] = { 0 };
    size_t data_idx = cwr__ws_write_header(ws, opcode, frame, len, fin);
    if (!cwr_buf_push_back(&ws->write_queue, frame, data_idx))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }
    size_t write_off = ws->write_queue.len;
    if (!cwr_buf_push_back(&ws->write_queue, data, len))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }
    if (ws->client_mode)
        cwr__ws_mask(&frame[data_idx - 4], &ws->write_queue.base[write_off], len);
    data_idx += len;
    if (!cwr_buf_push_back(&ws->write_queue_len, (const char *)&data_idx, sizeof(size_t)))
    {
        ws->io.err_type = CWR_E_INTERNAL;
        ws->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }
    cwr__ws_written(ws->stream); /* Trigger write if no pending frames */
    return CWR_E_WS_OK;
}

int cwr_ws_send (cwr_ws_t *ws, const char *data, size_t len, uint8_t opcode)
{
    return cwr_ws_send2(ws, data, len, opcode, 1);
}

int cwr_ws_close2 (cwr_ws_t *ws, uint16_t status, const char *data, uint8_t len)
{
    if (ws->state != CWR_WS_OPEN)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_W_WS_NOT_OPEN;
        return CWR_W_WS_NOT_OPEN;
    }
    if (len > 123)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_E_WS_CONTROL_FRAME_LEN;
        return CWR_E_WS_CONTROL_FRAME_LEN;
    }
    if (cwr_utf8_check(data, len)) /* must be utf8 */
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_E_WS_INVALID_UTF8;
        return CWR_E_WS_INVALID_UTF8;
    }
    char payload[125] = { 0 };
    uint16_t net_status = htobe16(status);
    memcpy(payload, &net_status, 2);
    memcpy(&payload[2], data, len);
    ws->requested_close = 1;
    ws->state = CWR_WS_CLOSING;
    cwr__ws_send_short_noq(ws, CWR_WS_OP_CLOSE, payload, 2 + len);
    return CWR_E_WS_OK;
}

int cwr_ws_close (cwr_ws_t *ws, uint16_t status)
{
    if (ws->state != CWR_WS_OPEN)
    {
        ws->io.err_type = CWR_E_WS;
        ws->io.err_code = CWR_W_WS_NOT_OPEN;
        return CWR_W_WS_NOT_OPEN;
    }
    char payload[2] = { 0 };
    uint16_t net_status = htobe16(status);
    memcpy(payload, &net_status, 2);
    ws->requested_close = 1;
    ws->state = CWR_WS_CLOSING;
    cwr__ws_send_short_noq(ws, CWR_WS_OP_CLOSE, payload, 2);
    return CWR_E_WS_OK;
}

int cwr_ws_shutdown (cwr_ws_t *ws)
{
    return cwr_ws_close(ws, CWR_WS_STATUS_NORMAL_CLOSURE);
}

void cwr_ws_free (cwr_ws_t *ws)
{
    if (ws->host_name)
        cwr_free(ws->m_ctx, ws->host_name);
    if (ws->resource_name)
        cwr_free(ws->m_ctx, ws->resource_name);

    if (ws->buffer.base)
        cwr_buf_free(&ws->buffer);
    if (ws->header_field.base)
        cwr_buf_free(&ws->header_field);
    if (ws->header_value.base)
        cwr_buf_free(&ws->header_value);
    if (ws->write_queue.base)
        cwr_buf_free(&ws->write_queue);
    if (ws->write_queue_len.base)
        cwr_buf_free(&ws->write_queue_len);
}
