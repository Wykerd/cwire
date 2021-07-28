#ifndef CWR_COMMON_H
#define CWR_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <uv.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

typedef struct cwr_malloc_state_s {
    size_t malloc_count;
    size_t malloc_size;
    size_t malloc_limit;
    void *data; 
} cwr_malloc_state_t;

typedef struct cwr_mallloc_funcs_s {
    void *(*cwr_malloc)(void *state, size_t size);
    void *(*cwr_realloc)(void *state, void *ptr, size_t size);
    void (*cwr_free)(void *state, void *ptr);
    size_t (*cwr_malloc_usable_size)(const void *ptr);
} cwr_malloc_funcs_t;

#define DEF_CWR_ALLOC_CONTEXT(state)   \
    {                                   \
        cwr_malloc_funcs_t mf;          \
        state ms;                       \
    }

typedef struct cwr_malloc_ctx_s 
    DEF_CWR_ALLOC_CONTEXT(cwr_malloc_state_t) 
cwr_malloc_ctx_t;

typedef enum cwr_err {
    CWR_E_OK = 0,
    CWR_E_INTERNAL,
    CWR_E_UNDERLYING,
    CWR_E_WS,
    CWR_E_LLHTTP,
    CWR_E_USER,
    CWR_E_UV,
    CWR_E_SSL,
    CWR_E_SSL_ERR,
    CWR_E_SSL_BIO_IO,
} cwr_err_t;

typedef enum cwr_intr_err {
    CWR_E_INTERNAL_OK = 0,
    CWR_E_INTERNAL_OOM,
    CWR_E_INTERNAL_URLPARSE,
    CWR_E_UNREACHABLE
} cwr_intr_err_t;

typedef enum cwr_usr_err {
    CWR_E_USER_OK = 0,
    CWR_E_USER_READER_ERROR,
    CWR_E_USER_HTTP_FIELD,
    CWR_E_USER_WS_INVALID_SCHEMA,
    CWR_E_USER_WS_FRAGMENT,
    CWR_E_USER_WS_PROTOCOL_VAL
} cwr_usr_err_t;

typedef enum cwr_ws_err {
    CWR_E_WS_OK = 0,
    CWR_E_WS_INVALID_STATUS,
    CWR_E_WS_REDIRECT,
    CWR_E_WS_INVALID_CONNECTION_HEADER,
    CWR_E_WS_INVALID_UPGRADE_HEADER,
    CWR_E_WS_INVALID_SHA1_KEY,
    CWR_E_WS_INVALID_PROTOCOL,
    CWR_E_WS_RESERVED_BIT_SET,
    CWR_E_WS_SERVER_MASKING,
    CWR_E_WS_PAYLOAD_LENGTH
} cwr_ws_err_t;

#define DEF_CWR_LINK_IO_SIGNATURE(classname, type) \
    typedef int (*cwr_ ## classname ## _io)(type *, const void *, size_t)

#define DEF_CWR_LINK_CB_SIGNATURE(classname, type) \
    typedef void (*cwr_ ## classname ## _cb)(type *)

typedef struct cwr_linkable_s cwr_linkable_t;

#define DEF_CWR_LINK_CLS(classname, parent) \
    typedef struct cwr_ ## classname ## _s cwr_ ## classname ## _t;     \
    DEF_CWR_LINK_IO_SIGNATURE(classname, parent);                       \
    DEF_CWR_LINK_CB_SIGNATURE(classname, parent);                       \
    struct cwr_ ## classname ## _s {                                    \
        cwr_linkable_t *child;                                          \
        cwr_ ## classname ## _io reader;                                \
        cwr_ ## classname ## _io writer;                                \
        cwr_ ## classname ## _cb on_error;                              \
        cwr_ ## classname ## _io on_read;                               \
        cwr_ ## classname ## _io on_write;                              \
        cwr_err_t err_type;                                             \
        ssize_t err_code;                                               \
    }

DEF_CWR_LINK_CLS(link, cwr_linkable_t);

struct cwr_linkable_s {
    void *data;
    cwr_link_t io;
};

const char *cwr_err_get_str(cwr_linkable_t *link);

void cwr_malloc_ctx_new_ex (cwr_malloc_ctx_t *ctx, const cwr_malloc_funcs_t *mf);
void cwr_malloc_ctx_new (cwr_malloc_ctx_t *ctx);
int cwr_malloc_ctx_set_limit (cwr_malloc_ctx_t *ctx, size_t limit);
void cwr_malloc_ctx_dump_leaks (cwr_malloc_ctx_t *ctx);
void *cwr_malloc (cwr_malloc_ctx_t *ctx, size_t size);
void cwr_free (cwr_malloc_ctx_t *ctx, void *ptr);
void *cwr_realloc (cwr_malloc_ctx_t *ctx, void *ptr, size_t size);
void *cwr_mallocz (cwr_malloc_ctx_t *ctx, size_t size);

typedef struct cwr_buf_s {
    char* base;
    size_t len;
    size_t size;
    cwr_malloc_ctx_t *m_ctx;
} cwr_buf_t;

void *cwr_buf_malloc (cwr_buf_t *buf, cwr_malloc_ctx_t *ctx, size_t initial_size);
void *cwr_buf_resize (cwr_buf_t *buf, size_t size);
void *cwr_buf_push_back (cwr_buf_t *buf, const char *src, size_t len);
void cwr_buf_shift (cwr_buf_t *buf, size_t len);
void cwr_buf_free (cwr_buf_t *buf);

#endif