#include <cwire/common.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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
static const char user_error[] = "User defined method error";
static const char *internal_errors[] = {
    "OK",
    "Out of memory",
    "Failed to parse URL",
    "Unreachable code reached"
};

#include <openssl/err.h>

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
        return user_error;

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

void *cwr_buf_push_back (cwr_buf_t *buf, char *src, size_t len)
{

    if (buf->size < (buf->len + len))
        if (!cwr_buf_resize(buf, buf->len + len))
            return NULL;
        
    char *sp = buf->base + buf->len;

    memcpy(sp, src, len);
    buf->len += len;

    return sp; 
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
