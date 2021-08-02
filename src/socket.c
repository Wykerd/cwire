#include <cwire/socket.h>
#include <cwire/url.h>
#include <cwire/net.h>
#include <string.h>
#include <stdlib.h>

#include <cwire/no_malloc.h>

static void cwr__sock_write_cb (uv_write_t* req, int status)
{
    cwr_sock_t *sock = req->handle->data;

    sock->io.write_pending--;

    if (status != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = status;
        if (sock->io.on_error)
            sock->io.on_error(sock);
        goto exit;
    }

    if (sock->io.on_write) 
        sock->io.on_write(sock);

exit:
    cwr_free(sock->m_ctx, req);
}

int cwr_sock_writer (cwr_sock_t *sock, const char *buf, size_t len) 
{
    int r = 0;

    uv_write_t *write = cwr_malloc(sock->m_ctx, sizeof(uv_write_t));

    if (!write)
    {
        sock->io.err_type = CWR_E_INTERNAL;
        sock->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    uv_buf_t buffer = {
        .base = (char *)buf,
        .len = len
    };

    r = uv_write(write, (uv_stream_t*)&sock->h_tcp, &buffer, 1, cwr__sock_write_cb);

    if (r != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = r;
        return r;
    }

    sock->io.write_pending++;

    return 0;
}

int cwr_sock_init (cwr_malloc_ctx_t *m_ctx, uv_loop_t *loop, cwr_sock_t *sock) 
{
    memset(sock, 0, sizeof(cwr_sock_t));
    int r;
    sock->loop = loop;
    sock->m_ctx = m_ctx;

    r = uv_tcp_init(loop, &sock->h_tcp);
    if (r != 0)
        return r;

    sock->h_tcp.data = sock;

    sock->io.writer = cwr_sock_writer;

    return 0;
}

static void cwr__sock_connect_cb (uv_connect_t *req, int status)
{
    cwr_sock_t *sock = req->handle->data;

    if (status != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = status;
        if (sock->io.on_error)
            sock->io.on_error(sock);
        goto exit;
    }

    if (sock->on_connect)
        sock->on_connect(sock);

exit:
    cwr_free(sock->m_ctx, req);
}

int cwr_sock_connect (cwr_sock_t *sock, struct sockaddr *addr)
{
    uv_connect_t *conn_req = cwr_malloc(sock->m_ctx, sizeof(uv_connect_t));

    if (!conn_req)
    {
        sock->io.err_type = CWR_E_INTERNAL;
        sock->io.err_code = CWR_E_INTERNAL_OOM;
        return CWR_E_INTERNAL_OOM;
    }

    int r = uv_tcp_connect(conn_req, &sock->h_tcp, addr, cwr__sock_connect_cb);

    if (r != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = r;
        return r;
    }

    return 0;
}

static void cwr__sock_getaddrinfo_cb (uv_getaddrinfo_t *req, int status, struct addrinfo* res)
{
    cwr_sock_t *sock = req->data;

    if (status != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = status;
        if (sock->io.on_error)
            sock->io.on_error(sock);
        goto cleanup;
    }

    int r = cwr_sock_connect(sock, res->ai_addr);

    if (r != 0)
    {
        if (sock->io.on_error)
            sock->io.on_error(sock);
    }

cleanup:
    uv_freeaddrinfo(res);
    cwr_free(sock->m_ctx, req);
}

int cwr_sock_connect_host (cwr_sock_t *sock, const char *hostname, const char *port) 
{
    uv_getaddrinfo_t *addrinfo_req = cwr_malloc(sock->m_ctx, sizeof(uv_getaddrinfo_t));

    addrinfo_req->data = sock;

    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int n = cwr_net_is_numeric_host_v(hostname);
    if (n)
    {
        int r;
        switch (n)
        {
        case 4:
            {
                struct sockaddr_in dst;
                r = uv_ip4_addr(hostname, atoi(port), &dst);
                cwr_sock_connect(sock, (struct sockaddr *)&dst);
            }
            break;
        
        case 6:
            {
                struct sockaddr_in6 dst;
                r = uv_ip6_addr(hostname, atoi(port), &dst);
                cwr_sock_connect(sock, (struct sockaddr *)&dst);
            }
            break;

        default:
            {
                sock->io.err_type = CWR_E_INTERNAL;
                sock->io.err_code = CWR_E_UNREACHABLE;
                return CWR_E_UNREACHABLE;
            }
        }

        if (unlikely(r != 0))
        {
            sock->io.err_type = CWR_E_UV;
            sock->io.err_code = r;
            return r;
        };

        return 0;
    }

    int r = uv_getaddrinfo(
        sock->loop,
        addrinfo_req,
        cwr__sock_getaddrinfo_cb,
        hostname, port,
        &hints    
    );

    if (r != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = r;
        return r;
    }

    return 0;
}

int cwr_sock_connect_url (cwr_sock_t *sock, const char *url, size_t len)
{
    struct http_parser_url u;
    http_parser_url_init(&u);

    if (http_parser_parse_url(url, len, 0, &u))
    {
        sock->io.err_type = CWR_E_INTERNAL;
        sock->io.err_code = CWR_E_INTERNAL_URLPARSE;
        return CWR_E_INTERNAL_URLPARSE;
    }

    char *host, *port;

    if (!u.field_data[UF_PORT].len)
    {
        port = cwr_mallocz(sock->m_ctx, 6);
        if (!port)
        {
            sock->io.err_type = CWR_E_INTERNAL;
            sock->io.err_code = CWR_E_INTERNAL_OOM;
            return CWR_E_INTERNAL_OOM;
        }
        switch (u.field_data[UF_SCHEMA].len)
        {
        case 5:
            if (!strncasecmp(url + u.field_data[UF_SCHEMA].off, "https", u.field_data[UF_SCHEMA].len))
            {
                strcpy(port, "443");
            }
            break;

        case 4:
            if (!strncasecmp(url + u.field_data[UF_SCHEMA].off, "http", u.field_data[UF_SCHEMA].len))
            {
                strcpy(port, "80");
            }
            break;

        case 3:
            if (!strncasecmp(url + u.field_data[UF_SCHEMA].off, "wss", u.field_data[UF_SCHEMA].len))
            {
                strcpy(port, "443");
            }
            break;

        case 2:
            if (!strncasecmp(url + u.field_data[UF_SCHEMA].off, "ws", u.field_data[UF_SCHEMA].len))
            {
                strcpy(port, "80");
            }
            break;
        
        default:
            break;
        }
    }
    else 
    {
        port = cwr_mallocz(sock->m_ctx, u.field_data[UF_PORT].len + 1);
        if (!port)
        {
            sock->io.err_type = CWR_E_INTERNAL;
            sock->io.err_code = CWR_E_INTERNAL_OOM;
            return CWR_E_INTERNAL_OOM;
        }
        memcpy(port, url + u.field_data[UF_PORT].off, u.field_data[UF_PORT].len);
    }

    host = cwr_mallocz(sock->m_ctx, u.field_data[UF_HOST].len + 1);
    if (!host)
    {
        sock->io.err_type = CWR_E_INTERNAL;
        sock->io.err_code = CWR_E_INTERNAL_OOM;
        cwr_free(sock->m_ctx, port);
        return CWR_E_INTERNAL_OOM;
    }
    memcpy(host, url + u.field_data[UF_HOST].off, u.field_data[UF_HOST].len);

    int r = cwr_sock_connect_host(sock, host, port);

    cwr_free(sock->m_ctx, port);
    cwr_free(sock->m_ctx, host);

    return r;
}

static void cwr__sock_close_cb (uv_handle_t *handle) 
{
    cwr_sock_t *sock = handle->data;

    if (sock->on_close)
        sock->on_close(sock);
}

int cwr_sock_shutdown (cwr_sock_t *sock)
{
    int r = uv_tcp_close_reset(&sock->h_tcp, cwr__sock_close_cb);

    if (r != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = r;
        return r;
    }

    return 0;
}

static void cwr__sock_alloc_cb (uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) 
{
    cwr_sock_t *sock = handle->data;
    buf->base = (char*)cwr_malloc(sock->m_ctx, suggested_size);
    buf->len = suggested_size;
}

static void cwr__sock_read_cb (uv_stream_t *handle, ssize_t nread, const uv_buf_t * buf) 
{
    cwr_sock_t *sock = handle->data;

    if (nread > 0)
    {
        int r = sock->io.reader(sock, buf->base, nread);
        if (r)
        {
            if (sock->io.on_error)
                sock->io.on_error(sock);
            goto exit;
        }
        if (sock->io.on_read)
        {
            r = sock->io.on_read(sock, buf->base, nread);
            if (r)
            {
                if (sock->io.on_error)
                    sock->io.on_error(sock);
                goto exit;
            }
        }
    } 
    else 
    {
        if (nread == UV_EOF)
        {
            cwr_sock_shutdown(sock);

            goto exit;
        }
        uv_read_stop(handle);

        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = nread;
        if (sock->io.on_error)
            sock->io.on_error(sock);
    }
exit:
    cwr_free(sock->m_ctx, buf->base);
}

int cwr_sock_read_start (cwr_sock_t *sock) 
{
    int r = uv_read_start((uv_stream_t *)&sock->h_tcp, cwr__sock_alloc_cb, cwr__sock_read_cb);

    if (r != 0)
    {
        sock->io.err_type = CWR_E_UV;
        sock->io.err_code = r;
        return r;
    }

    return 0;
}

int cwr_sock_write (cwr_sock_t *sock, const void *buf, size_t len)
{
    return sock->io.writer(sock, buf, len);
}
