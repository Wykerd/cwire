#include <cwire/common.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

/* Memory allocation implementation is from QuickJS, 
 * which is licenced under the MIT license. It is available here:
 * https://bellard.org/quickjs/
 */
#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__linux__)
#include <malloc.h>
#endif
#if defined(__APPLE__)
#define MALLOC_OVERHEAD  0
#else
#define MALLOC_OVERHEAD  8
#endif
#include <assert.h>

static inline size_t js_def_malloc_usable_size(void *ptr)
{
#if defined(__APPLE__)
    return malloc_size(ptr);
#elif defined(_WIN32)
    return _msize(ptr);
#elif defined(EMSCRIPTEN)
    return 0;
#elif defined(__linux__)
    return malloc_usable_size(ptr);
#else
    /* change this to `return 0;` if compilation fails */
    return malloc_usable_size(ptr);
#endif
}

static inline size_t cwr__def_malloc_usable_size(void *ptr)
{
#if defined(__APPLE__)
    return malloc_size(ptr);
#elif defined(_WIN32)
    return _msize(ptr);
#elif defined(EMSCRIPTEN)
    return 0;
#elif defined(__linux__)
    return malloc_usable_size(ptr);
#else
    /* change this to `return 0;` if compilation fails */
    return malloc_usable_size(ptr);
#endif
}

static void *cwr__def_malloc(cwr_malloc_state_t *s, size_t size)
{
    void *ptr;

    /* Do not allocate zero bytes: behavior is platform dependent */
    assert(size != 0);

    if (unlikely(s->malloc_size + size > s->malloc_limit))
        return NULL;

    ptr = malloc(size);
    if (!ptr)
        return NULL;

    s->malloc_count++;
    s->malloc_size += cwr__def_malloc_usable_size(ptr) + MALLOC_OVERHEAD;
    return ptr;
}

static void cwr__def_free(cwr_malloc_state_t *s, void *ptr)
{
    if (!ptr)
        return;

    s->malloc_count--;
    s->malloc_size -= cwr__def_malloc_usable_size(ptr) + MALLOC_OVERHEAD;
    free(ptr);
}

static void *cwr__def_realloc(cwr_malloc_state_t *s, void *ptr, size_t size)
{
    size_t old_size;

    if (!ptr) {
        if (size == 0)
            return NULL;
        return cwr__def_malloc(s, size);
    }
    old_size = cwr__def_malloc_usable_size(ptr);
    if (size == 0) {
        s->malloc_count--;
        s->malloc_size -= old_size + MALLOC_OVERHEAD;
        free(ptr);
        return NULL;
    }
    if (s->malloc_size + size - old_size > s->malloc_limit)
        return NULL;

    ptr = realloc(ptr, size);
    if (!ptr)
        return NULL;

    s->malloc_size += cwr__def_malloc_usable_size(ptr) - old_size;
    return ptr;
}

#include <cwire/no_malloc.h>

static const cwr_malloc_funcs_t def_malloc_funcs = {
    (void *(*)(void *, size_t))cwr__def_malloc,
    (void *(*)(void *, void *, size_t))cwr__def_realloc,
    (void (*)(void *, void *))cwr__def_free,
#if defined(__APPLE__)
    malloc_size,
#elif defined(_WIN32)
    (size_t (*)(const void *))_msize,
#elif defined(EMSCRIPTEN)
    NULL,
#elif defined(__linux__)
    (size_t (*)(const void *))malloc_usable_size,
#else
    /* change this to `NULL,` if compilation fails */
    malloc_usable_size,
#endif
};

static size_t cwr__malloc_usable_size_unknown (const void *ptr)
{
    return 0;
}

void cwr_malloc_ctx_new_ex (cwr_malloc_ctx_t *ctx, const cwr_malloc_funcs_t *mf)
{
    memset(ctx, 0, sizeof(cwr_malloc_ctx_t));
    ctx->ms.malloc_limit = -1;

    ctx->mf = *mf;

    if (!ctx->mf.cwr_malloc_usable_size)
        ctx->mf.cwr_malloc_usable_size = cwr__malloc_usable_size_unknown;
}

void cwr_malloc_ctx_new (cwr_malloc_ctx_t *ctx)
{
    return cwr_malloc_ctx_new_ex(ctx, &def_malloc_funcs);
}

int cwr_malloc_ctx_set_limit (cwr_malloc_ctx_t *ctx, size_t limit)
{
    ctx->ms.malloc_limit = limit;
}

void cwr_malloc_ctx_dump_leaks (cwr_malloc_ctx_t *ctx)
{
    if (ctx->ms.malloc_count > 0)
        printf("Memory leak: %"PRIu64" bytes lost in %"PRIu64" block%s\n",
            (uint64_t)(ctx->ms.malloc_size),
            (uint64_t)(ctx->ms.malloc_count), &"s"[ctx->ms.malloc_count > 1]);
}

void *cwr_malloc (cwr_malloc_ctx_t *ctx, size_t size) 
{
    return ctx->mf.cwr_malloc(&ctx->ms, size);
}
void cwr_free (cwr_malloc_ctx_t *ctx, void *ptr)
{
    ctx->mf.cwr_free(&ctx->ms, ptr);
}
void *cwr_realloc (cwr_malloc_ctx_t *ctx, void *ptr, size_t size)
{
    return ctx->mf.cwr_realloc(&ctx->ms, ptr, size);
}
void *cwr_mallocz (cwr_malloc_ctx_t *ctx, size_t size)
{
    void *ptr;
    ptr = cwr_malloc(ctx, size);
    if (!ptr)
        return NULL;
    return memset(ptr, 0, size);
}

static const char unknown_error[] = "Unknown error";
static const char llhttp_error[] = "llhttp error";
static const char user_error[] = "User defined method error";
static const char *internal_errors[] = {
    "OK",
    "Out of memory",
    "Failed to parse URL",
    "Unreachable code reached"
};
static const char *user_errors[] = {
    "OK",
    "I/O Error. Reader threw an non 0 return.",
    "I/O Error. Writer threw an non 0 return.",
    "Invalid HTTP field",
    "Invalid Resource Schema in WebSocket Connect",
    "WebSocket URI cannot contain a fragment",
    "Invalid WebSocket subprotocol value"
};
static const char *ws_errors[] = {
    "OK",
    "WS: Invalid HTTP statuscode during handshake.",
    "WS: Want redirect.",
    "WS: Invalid connection header value during handshake",
    "WS: Invalid upgrade header value during handshake",
    "WS: Invalid Sec-WebSocket-Accept header SHA1 hash during handshake",
    "WS: Invalid protocol selected during handshake",
    "WS: Reserved bit set in incoming frame",
    "WS: Server has sent a masked frame",
    "WS: Payload length overflow in incoming frame",
    "WS: The fragments of one message is interleaved between the fragments of another message",
    "WS: Received continuation frame while not currently receiving a fragmented message",
    "WS: Received control frame with unset FIN",
    "WS: Received unknown opcode",
    "WS: Received control frame with length > 125",
    "WS: Invalid UTF-8",
    "WS: Connection state is not OPEN"
};

#include <openssl/err.h>
#include <llhttp.h>

int cwr_linkable_has_pending_write(cwr_linkable_t *link)
{
    if (link->io.write_pending)
        return 1;
    if (link->io.parent)
        return cwr_linkable_has_pending_write(link->io.parent);
    return 0;
}

const char *cwr_err_get_str(cwr_linkable_t *link)
{
    switch (link->io.err_type)
    {
    case CWR_E_INTERNAL:
        {
            if ((link->io.err_code >= 0) && (link->io.err_code < (sizeof(internal_errors) / sizeof(char *))))
            {
                return internal_errors[link->io.err_code];
            }
            return unknown_error;
        }

    case CWR_E_USER:
        {
            if ((link->io.err_code >= 0) && (link->io.err_code < (sizeof(user_errors) / sizeof(char *))))
            {
                return user_errors[link->io.err_code];
            }
            return unknown_error;
        }

    case CWR_E_UNDERLYING:
        return unknown_error; // TODO: Underlying error

    case CWR_E_WS:
        {
            if ((link->io.err_code >= 0) && (link->io.err_code < (sizeof(ws_errors) / sizeof(char *))))
            {
                return ws_errors[link->io.err_code];
            }
            return unknown_error;
        }

    case CWR_E_LLHTTP:
        return llhttp_error;

    case CWR_E_UV:
        return uv_err_name(link->io.err_code);

    case CWR_E_SSL:
    case CWR_E_SSL_ERR:
    case CWR_E_SSL_BIO_IO:
        return ERR_error_string(link->io.err_code, NULL);
    
    default:
        return unknown_error;
    }
}

void *cwr_buf_malloc (cwr_buf_t *buf, cwr_malloc_ctx_t *ctx, size_t initial_size)
{
    buf->m_ctx = ctx;
    buf->base = cwr_malloc(ctx, initial_size);
    buf->len = 0;
    buf->size = initial_size;
    return buf->base;
}

void *cwr_buf_resize (cwr_buf_t *buf, size_t size)
{
    buf->base = cwr_realloc(buf->m_ctx, buf->base, size);
    buf->size = size;
    if (buf->len > buf->size)
        buf->len = buf->size;
    return buf->base;
}

void *cwr_buf_push_back (cwr_buf_t *buf, const char *src, size_t len)
{

    if (buf->size < (buf->len + len))
        if (!cwr_buf_resize(buf, buf->len + len))
            return NULL;
        
    char *sp = buf->base + buf->len;

    memcpy(sp, src, len);
    buf->len += len;

    return sp; 
}

void *__attribute__((format(printf, 2, 3))) cwr_buf_printf (cwr_buf_t *buf, const char *fmt, ...)
{
    va_list ap;
    int len;
    char buff[256];

    va_start(ap, fmt);
    len = vsnprintf(buff, sizeof(buff), fmt, ap);
    va_end(ap);
    if (len < sizeof(buff))
        return cwr_buf_push_back(buf, buff, len);

    if (buf->size < (buf->len + len + 1))
        if (!cwr_buf_resize(buf, buf->len + len + 1))
            return NULL;
    
    char *sp = buf->base + buf->len;

    va_start(ap, fmt);
    vsnprintf(sp, buf->size - buf->len, fmt, ap);
    va_end(ap);

    buf->len += len;

    return sp; 
}

void *cwr_buf_puts (cwr_buf_t *buf, const char *s)
{
    return cwr_buf_push_back(buf, s, strlen(s));
}

void *cwr_buf_push_front (cwr_buf_t *buf, const char *src, size_t len)
{
    if (buf->size < (buf->len + len))
        if (!cwr_buf_resize(buf, buf->len + len))
            return NULL;
    for (size_t i = 0; i < buf->len; i++)
        buf->base[buf->len - 1 + len - i] = buf->base[buf->len - 1 - i];
    
    memcpy(buf->base, src, len);
    buf->len += len;

    return buf->base;
}

void cwr_buf_shift (cwr_buf_t *buf, size_t len)
{
    memmove(buf->base, buf->base+len, buf->len-len);
    buf->len -= len;
}

void cwr_buf_free (cwr_buf_t *buf)
{
    cwr_free(buf->m_ctx, buf->base);
    buf->base = NULL;
    buf->size = 0;
    buf->len = 0;
}

/**
 * Credit:
 * Markus Kuhn <http://www.cl.cam.ac.uk/~mgk25/> -- 2005-03-30
 * License: http://www.cl.cam.ac.uk/~mgk25/short-license.html
 * Available: https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
 */
const char *cwr_utf8_check(const char *s, size_t len)
{
    size_t i = 0;
    while (i < len)
    {
        size_t j = i + 8;

        if (j <= len)
        {
            //
            // Read 8 bytes and check if they are ASCII.
            //
            uint64_t chunk;
            memcpy(&chunk, s + i, 8);

            if ((chunk & 0x8080808080808080) == 0x00)
            {
                i = j;
                continue;
            }
        }

        while ((s[i] & 0x80) == 0x00)
        { // 0xxxxxxx
            if (++i == len)
            {
                return NULL;
            }
        }

        if ((s[i] & 0xe0) == 0xc0)
        {
            /* 110XXXXx 10xxxxxx */
            if (i + 1 == len ||
                (s[i + 1] & 0xc0) != 0x80 ||
                (s[i] & 0xfe) == 0xc0) /* overlong? */
                return s + 1;
            else
                i += 2;
        }
        else if ((s[i] & 0xf0) == 0xe0)
        {
            /* 1110XXXX 10Xxxxxx 10xxxxxx */
            if (i + 2 >= len ||
                (s[i + 1] & 0xc0) != 0x80 ||
                (s[i + 2] & 0xc0) != 0x80 ||
                (s[i] == 0xe0 && (s[i + 1] & 0xe0) == 0x80) || /* overlong? */
                (s[i] == 0xed && (s[i + 1] & 0xe0) == 0xa0) || /* surrogate? */
                (s[i] == 0xef && s[i + 1] == 0xbf &&
                    (s[i + 2] & 0xfe) == 0xbe)) /* U+FFFE or U+FFFF? */
                return s + i;
            else
                i += 3;
        }
        else if ((s[i] & 0xf8) == 0xf0)
        {
            /* 11110XXX 10XXxxxx 10xxxxxx 10xxxxxx */
            if (i + 3 >= len ||
                (s[i + 1] & 0xc0) != 0x80 ||
                (s[i + 2] & 0xc0) != 0x80 ||
                (s[i + 3] & 0xc0) != 0x80 ||
                (s[i] == 0xf0 && (s[i + 1] & 0xf0) == 0x80) ||    /* overlong? */
                (s[i] == 0xf4 && s[i + 1] > 0x8f) || s[i] > 0xf4) /* > U+10FFFF? */
                return s + i;
            else
                i += 4;
        }
        else
            return s + i;
    }

    return NULL;
}
