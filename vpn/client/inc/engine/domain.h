#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/**
 * Resolves a hostname string into an IPv4 struct in_addr.
 * 
 * @param hostname The domain string or IP string (e.g., "server.home" or "192.168.0.100")
 * @param addr Output pointer to struct in_addr where the resolved IP will be stored
 * @return int 0 on success, -1 on failure
 */
int resolve_hostname_ipv4(const char *hostname, struct in_addr *addr);

/**
 * Resolves a hostname string into an IPv6 struct in6_addr.
 * 
 * @param hostname The domain string or IP string (e.g., "server.home" or "2001:db8::1")
 * @param addr Output pointer to struct in6_addr where the resolved IP will be stored
 * @return int 0 on success, -1 on failure
 */
int resolve_hostname_ipv6(const char *hostname, struct in6_addr *addr);

/**
 * Resolves a hostname string into a human-readable IPv4 address string.
 * 
 * @param hostname Domain string or IP string (e.g., "server.home")
 * @param ip_buf Buffer to store the output IP string
 * @param ip_buf_len Size of ip_buf (should be at least INET_ADDRSTRLEN)
 * @return int 0 on success, -1 on failure
 */
int resolve_hostname_ipv4_str(const char *hostname, char *ip_buf, size_t ip_buf_len);

/**
 * Resolves a hostname string into a human-readable IPv6 address string.
 * 
 * @param hostname Domain string or IP string (e.g., "server.home" or "2001:db8::1")
 * @param ip_buf Buffer to store the output IP string
 * @param ip_buf_len Size of ip_buf (should be at least INET6_ADDRSTRLEN)
 * @return int 0 on success, -1 on failure
 */
int resolve_hostname_ipv6_str(const char *hostname, char *ip_buf, size_t ip_buf_len);



/**
 * Resolves a hostname string to a generic sockaddr_storage structure and string.
 * Supports both IPv4 (AF_INET) and IPv6 (AF_INET6).
 * 
 * @param hostname Domain string or IP string (e.g., "server.home")
 * @param generic_addr Output pointer to struct sockaddr_storage
 * @return int 0 on success, -1 on failure
 */
int resolve_hostname(const char *hostname, struct sockaddr_storage *addr);

/**
 * @brief Converts a generic socket address structure to a human-readable IP string.
 *
 * This function extracts the binary IP address from a populated \c sockaddr_storage
 * structure (supporting both IPv4 and IPv6) and converts it into a null-terminated
 * presentation string using \c inet_ntop().
 *
 * @param[in]  addr       Pointer to the populated \c sockaddr_storage structure.
 * @param[out] ip_buf     Buffer where the converted IP address string will be stored.
 * @param[in]  ip_buf_len Capacity of \p ip_buf in bytes. Must be at least \c INET6_ADDRSTRLEN (46 bytes).
 *
 * @return \c 0 on success, or \c -1 if an error occurs (e.g., NULL pointers, buffer too small, or unsupported address family).
 *
 * @note This function is thread-safe and reentrant.
 */
int sockaddr_to_str(const struct sockaddr_storage *addr, char *ip_buf, size_t ip_buf_len);