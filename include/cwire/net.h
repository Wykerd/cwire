#ifndef CWR_NET_H
#define CWR_NET_H

int cwr_net_is_numeric_host_af (const char *hostname, int family);
int cwr_net_is_numeric_host_v6 (const char *hostname);
int cwr_net_is_numeric_host_v4 (const char *hostname);
int cwr_net_is_numeric_host_v (const char *hostname);
int cwr_net_is_numeric_host (const char *hostname);

/**
 * Initializes OpenSSL globals
 */
void cwr_openssl_init ();

#endif