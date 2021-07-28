#ifndef CWR_WS_H
#define CWR_WS_H

#include "./common.h"
#include <llhttp.h>
#include <openssl/sha.h>

/* Handshake defines */
#define CWR_WS_KEY_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
/* Placeholder data for client nonce to be written into */
#define CWR_WS_CLIENT_NONCE "xxxxxxxxxxxxxxxxxxxxxxxx" 
/* Full unhashed key */
#define CWR_WS_KEY CWR_WS_CLIENT_NONCE CWR_WS_KEY_GUID
/* Current RFC 6455 REQUIRES version to be 13 */
#define CWR_WS_VERSION "13"
#define CWR_WS_HEADERS \
    "\r\n"                                              \
    "Upgrade: websocket\r\n"                            \
    "Connection: Upgrade\r\n"                           \
    "Sec-WebSocket-Version: " CWR_WS_VERSION "\r\n"     \

typedef struct cwr_ws_s cwr_ws_t;

DEF_CWR_LINK_CLS(ws_link, cwr_ws_t);

typedef void (*cwr_ws_cb)(cwr_ws_t *);

typedef enum cwr_ws_state {
    CWR_WS_INIT = 0,
    CWR_WS_CONNECTING, /* Sent handshake */
    CWR_WS_CONNECTED, /* Received and verified handshake */
    CWR_WS_CLOSING, /* Sent closing packet */
    CWR_WS_CLOSED, /* Closing handshake is done */
    CWR_WS_STATE_HANDSHAKE_FAILED
} cwr_ws_state_t;

struct cwr_ws_s {
    void *data; /* Opaque data */
    cwr_ws_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */

    cwr_ws_cb on_close; /* ws connection has closed */
    cwr_ws_cb on_message_complete; /* inbound message is completely read */

    cwr_linkable_t *stream; /* Underlying TCP/TLS implementation */

    /* The WS implementation does not manage the memory of protocols or handshake_headers */
    const char **protocols; /* NULL terminated array of protocols (tokens) */ 

    char *protocol_selected;

    /** 
     * NULL terminated array of strings. 
     * Header fields and values are interleaved. 
     * You MUST NOT include any of the following headers: Host, Connection, Upgrade, or any Sec-WebSocket-*
     * @example { "User-Agent", "cwire/0.0.0", "Origin", "http://example.com", NULL }
     */
    const char **handshake_headers; 

    llhttp_t http_parser;
    llhttp_settings_t http_parser_settings;

    /* WebSocket URI */
    int is_secure;
    char *host_name; /* TODO: FREE */
    char *resource_name; /* TODO: FREE */

    uint8_t key[sizeof(CWR_WS_KEY)]; /* Key used in handshake */
    uint8_t key_hash[28]; /* base64 encoded SHA1 hash of key for verification purposes */

    //cwr_ws_header_state_t header_state;
    void *(*on_header_value)(cwr_ws_t *ws);
    void *(*on_header_field)(cwr_ws_t *ws);
    cwr_buf_t header_field;
    cwr_buf_t header_value;

    cwr_ws_state_t state;
};

int cwr_ws_init (cwr_malloc_ctx_t *m_ctx, cwr_linkable_t *stream, cwr_ws_t *ws);
/**
 * Performs opening handshake.
 * This method does not open the underlying connection itself. 
 * It is up to you to correctly open the connection to the server with the host and port from the given url.
 * If a connection could not be made to the server DO NOT call this method.
 * For compliance to RFC 6455 the underlying TLS connection MUST use the SNI TLS extension during handshake
 * This can be done by calling `cwr_tls_connect_with_sni` instead of `cwr_tls_connect`
 */
int cwr_ws_connect (cwr_ws_t *ws, const char* uri, size_t uri_len);
int cwr_ws_send (cwr_ws_t *ws, const void *buf, size_t len);
int cwr_ws_shutdown (cwr_ws_t *ws);
void cwr_ws_free (cwr_ws_t *ws);

#endif