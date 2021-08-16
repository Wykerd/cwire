#ifndef CWR_SOCKET_H
#define CWR_SOCKET_H

#include "./common.h"

typedef struct cwr_sock_s cwr_sock_t;

DEF_CWR_LINK_CLS(sock_link, cwr_sock_t);

typedef void (*cwr_sock_cb)(cwr_sock_t *);

struct cwr_sock_s {
    void *data;
    cwr_sock_link_t io; /* IO functions */
    cwr_malloc_ctx_t *m_ctx; /* Memory context */
    uv_loop_t *loop; /* Event loop used */
    cwr_sock_cb on_connect; /* Called once connected */
    cwr_sock_cb on_close; /* TCP close reset */
    cwr_sock_cb on_new_conn; /* on new connection */
    uv_tcp_t h_tcp; /* UV TCP handle */
};

int cwr_sock_writer (cwr_sock_t *sock, const char *buf, size_t len);
int cwr_sock_init (cwr_malloc_ctx_t *m_ctx, uv_loop_t *loop, cwr_sock_t *sock);

int cwr_sock_connect (cwr_sock_t *sock, struct sockaddr *addr);
int cwr_sock_connect_host (cwr_sock_t *sock, const char *hostname, const char *port);
int cwr_sock_connect_url (cwr_sock_t *sock, const char *url, size_t len);

int cwr_sock_bind (cwr_sock_t *sock, struct sockaddr *addr, unsigned int flags);
int cwr_sock_bind2 (cwr_sock_t *sock, struct sockaddr *addr);
int cwr_sock_bind_host (cwr_sock_t *sock, const char *hostname, const char *port);
int cwr_sock_bind_url (cwr_sock_t *sock, const char *url, size_t len);

int cwr_sock_listen (cwr_sock_t *sock, int backlog, cwr_sock_cb cb);
#define cwr_sock_listen2(sock, cb) cwr_sock_listen(sock, SOMAXCONN, cb)

int cwr_sock_accept (cwr_sock_t *server, cwr_sock_t *client);

int cwr_sock_write (cwr_sock_t *sock, const void *buf, size_t len);
int cwr_sock_read_start (cwr_sock_t *sock); 
int cwr_sock_shutdown (cwr_sock_t *sock);

#endif