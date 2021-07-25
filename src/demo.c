#include <cwire.h>
#include <string.h>

#include <cwire/no_malloc.h>

const char *url = "https://93.184.216.34/";
const char *request = 
    "GET / HTTP/1.1\r\n"
    "Host: 93.184.216.34\r\n"
    "Accept: */*\r\n"
    "User-Agent: cwire/0.0.0\r\n\r\n";

static void cwr__connect_cb (cwr_sock_t *sock)
{
    puts("CONNECT");
    cwr_tls_connect(sock->data);
    cwr_tls_write(sock->data, request, strlen(request));
    cwr_sock_read_start(sock);
}

static void cwr__err (cwr_sock_t *sock)
{
    puts(uv_err_name(sock->io.err_code));
}

static int cwr__reader (cwr_tls_t *tls, const void *buf, size_t len)
{
    fwrite(buf, 1, len, stdout);
    cwr_tls_shutdown(tls);
    return 0;
}   

static void cwr__tls_closed (cwr_tls_t *tls)
{
    puts("\nTLS HAS CLOSED");
    cwr_sock_shutdown(tls->sock);
}

int main () {
    puts("OK");
    cwr_openssl_init();
    cwr_malloc_ctx_t malloc_ctx;
    cwr_malloc_ctx_new(&malloc_ctx);
    cwr_sock_t sock;
    cwr_tls_t tls;
    cwr_sock_init(&malloc_ctx, uv_default_loop(), &sock);
    sock.io.on_error = cwr__err;
    sock.on_connect = cwr__connect_cb;
    cwr_tls_init(&malloc_ctx, &sock, &tls);
    sock.data = &tls;
    tls.io.reader = cwr__reader;
    tls.on_close = cwr__tls_closed;
    cwr_sock_connect_url(&sock, url, strlen(url));
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    cwr_tls_free(&tls);
    cwr_sec_ctx_free(&tls.sec_ctx);
    puts("DONE AND DONE");
    cwr_malloc_ctx_dump_leaks(&malloc_ctx);
}