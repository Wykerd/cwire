#include <cwire/net.h>

#include <uv.h>

#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

int cwr_net_is_numeric_host_af (const char *hostname, int family) {
    struct in6_addr dst;
    return uv_inet_pton(family, hostname, &dst) == 1;
}

int cwr_net_is_numeric_host_v6 (const char *hostname) {
    return cwr_net_is_numeric_host_af(hostname, AF_INET6);
}

int cwr_net_is_numeric_host_v4 (const char *hostname) {
    return cwr_net_is_numeric_host_af(hostname, AF_INET);
}

int cwr_net_is_numeric_host_v (const char *hostname) {
    int v = 0;
    if (cwr_net_is_numeric_host_v4(hostname)) 
        v = 4;
    else if (cwr_net_is_numeric_host_v6(hostname)) 
        v = 6;
    return v;
}

int cwr_net_is_numeric_host (const char *hostname) {
    return cwr_net_is_numeric_host_v6(hostname) ||
           cwr_net_is_numeric_host_v4(hostname);
}

void cwr_openssl_init () {
    /* Init openssl */
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}