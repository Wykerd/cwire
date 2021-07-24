#include <cwire.h>
#include <string.h>

const char *url = "http://www.example.com/";
const char *request = 
    "GET / HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Accept: */*\r\n"
    "User-Agent: cwire/0.0.0\r\n\r\n";

static void cwr__connect_cb (cwr_sock_t *sock)
{
    puts("CONNECT");
    cwr_sock_write(sock, request, strlen(request));
    cwr_sock_read_start(sock);
}

static void cwr__err (cwr_sock_t *sock)
{
    puts(uv_err_name(sock->io.err_code));
}

static int cwr__reader (cwr_sock_t *sock, const void *buf, size_t len)
{
    fwrite(buf, 1, len, stdout);
    return 0;
}   

int main () {
    puts("OK");
    cwr_malloc_ctx_t malloc_ctx;
    cwr_malloc_ctx_new(&malloc_ctx);
    cwr_sock_t sock;
    cwr_sock_init(&malloc_ctx, uv_default_loop(), &sock);
    sock.io.on_error = cwr__err;
    sock.on_connect = cwr__connect_cb;
    sock.io.reader = cwr__reader;
    cwr_sock_connect_url(&sock, url, strlen(url));
    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}