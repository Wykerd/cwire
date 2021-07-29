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
typedef void (*cwr_ws_close_cb)(cwr_ws_t *, uint16_t status, const char *reason, size_t reason_len);
typedef void (*cwr_ws_data_cb)(cwr_ws_t *, const char *, size_t);

typedef enum cwr_ws_state {
    CWR_WS_INIT = 0,
    CWR_WS_CONNECTING, /* Sent handshake */
    CWR_WS_OPEN, /* Received and verified handshake */
    CWR_WS_CLOSING, /* Sent closing packet */
    CWR_WS_CLOSED, /* Closing handshake is done */
    CWR_WS_FAILED
} cwr_ws_state_t;

#define CWR_WS_H_STATUS_OK          (1)
#define CWR_WS_H_UPGRADE_OK         (1 << 1)
#define CWR_WS_H_ACCEPT_OK          (1 << 2)
#define CWR_WS_H_CONNECTION_OK      (1 << 3)
#define CWR_WS_H_HANDSHAKE_ERR      (1 << 5)
#define CWR_WS_H_WANT_REDIRECT      (1 << 6)
#define CWR_WS_H_HAS_REDIRECT       (1 << 7)

#define CWR_WS_H_SUCCESSFUL         (CWR_WS_H_STATUS_OK | CWR_WS_H_UPGRADE_OK | CWR_WS_H_ACCEPT_OK | CWR_WS_H_CONNECTION_OK)

typedef enum cwr_ws_intr_state {
    CWR_WS_S_NEW = 0,
    CWR_WS_S_OP, // we have read the opcode and are moving on to the mask and len
    CWR_WS_S_LEN16,
    CWR_WS_S_LEN64,
    CWR_WS_S_MASKING_KEY,
    CWR_WS_S_PAYLOAD
} cwr_ws_intr_state_t;

#define CWR_WS_OP_CONTINUATION  ((char)0x00)
#define CWR_WS_OP_TEXT          ((char)0x01)
#define CWR_WS_OP_BINARY        ((char)0x02)
#define CWR_WS_OP_CLOSE         ((char)0x08)
#define CWR_WS_OP_PING          ((char)0x09)
#define CWR_WS_OP_PONG          ((char)0x0A)

#define CWR_WS_STATUS_NORMAL_CLOSURE        1000
#define CWR_WS_STATUS_GOING_AWAY            1001
#define CWR_WS_STATUS_PROTOCOL_ERROR        1002
#define CWR_WS_STATUS_UNEXCEPTABLE_DATA     1003
#define CWR_WS_STATUS_INVALID_TYPE          1007
#define CWR_WS_STATUS_POLICY_VIOLATION      1008
#define CWR_WS_STATUS_TOO_BIG               1009
#define CWR_WS_STATUS_EXPECTED_EXTENSION    1010
#define CWR_WS_STATUS_UNEXPECTED_ERROR      1011

struct cwr_ws_s {
    void *data; /* Opaque data */
    cwr_ws_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */

    cwr_ws_data_cb on_want_redirect; /* Fail the WebSocket Connection and retry with new location */
    /**
     * Fail the WebSocket Connection
     * the underlying stream SHOULD be closed in this callback
     */
    cwr_ws_cb on_fail; 
    /**
     * Called when a close frame is received.
     * Useful for logging errors. Do not call shutdown or close
     * methods from this callback. It is handled internally.
     */
    cwr_ws_close_cb on_receive_close;
    /**
     * The WebSocket Connection has been closed
     * the underlying stream MAY be closed in this callback
     * else you SHOULD wait for the server to close the connection
     */
    cwr_ws_cb on_close; /* ws connection has closed */
    cwr_ws_cb on_open;
    cwr_ws_data_cb on_message;
    cwr_ws_cb on_message_complete; /* inbound message is completely read */
    /**
     * Called when a pong is received 
     * Can be used to determine latency between a ping and a pong
     */
    cwr_ws_data_cb on_pong; 

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
    char *host_name;
    char *resource_name;

    uint8_t key[sizeof(CWR_WS_KEY)]; /* Key used in handshake */
    uint8_t key_hash[28]; /* base64 encoded SHA1 hash of key for verification purposes */

    uint64_t header_state;
    void *(*on_header_value)(cwr_ws_t *ws);
    void *(*on_header_field)(cwr_ws_t *ws);
    cwr_buf_t header_field;
    cwr_buf_t header_value;

    cwr_buf_t buffer;
    cwr_buf_t write_queue; /* Stores the frames themself */
    cwr_buf_t write_queue_len; /* Stores frame lengths */
    /* Internal frame parsing state */
    cwr_ws_intr_state_t intr_state;
    uint8_t opcode;
    uint8_t opcode_cont;
    uint8_t fin;
    uint8_t mask;
    uint64_t payload_len;
    uint8_t masking_key[4];
    /* Flags */
    uint8_t client_mode;
    uint8_t is_fragmented;
    uint8_t requested_close;

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
int cwr_ws_ping (cwr_ws_t *ws, const char *data, uint8_t len);
int cwr_ws_send2 (cwr_ws_t *ws, const char *data, size_t len, uint8_t opcode, int fin);
int cwr_ws_send (cwr_ws_t *ws, const char *data, size_t len, uint8_t opcode);
int cwr_ws_close2 (cwr_ws_t *ws, uint16_t status, const char *data, uint8_t len);
int cwr_ws_close (cwr_ws_t *ws, uint16_t status);
int cwr_ws_shutdown (cwr_ws_t *ws);
void cwr_ws_free (cwr_ws_t *ws);

#endif