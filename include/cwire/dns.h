#ifndef CWR_DNS_H
#define CWR_DNS_H

typedef void (*cwr_dns_resolve_cb)(void *opaque, struct sockaddr *addr);

int cwr_dns_is_numeric_host_af (const char *hostname, int family);
int cwr_dns_is_numeric_host_v6 (const char *hostname);
int cwr_dns_is_numeric_host_v4 (const char *hostname);
int cwr_dns_is_numeric_host_v (const char *hostname);
int cwr_dns_is_numeric_host (const char *hostname);

/**
 * Initializes OpenSSL globals
 */
void cwr_openssl_init ();

#endif