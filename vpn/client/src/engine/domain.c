#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include <errno.h>

#include "log.h"


int resolve_hostname_ipv4(const char *hostname, struct in_addr *addr) {
    if (!hostname || !addr) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // Force IPv4 only (struct in_addr)
    hints.ai_socktype = SOCK_DGRAM;  // UDP (QUIC context)

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        // gai_strerror(status) gives the human-readable error
        return -1;
    }

    if (!result || !result->ai_addr) {
        if (result) freeaddrinfo(result);
        return -1;
    }

    // Extract struct in_addr from the sockaddr_in structure
    struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;
    *addr = ipv4->sin_addr;

    freeaddrinfo(result);
    return 0;
}

int resolve_hostname_ipv6(const char *hostname, struct in6_addr *addr) {
    if (!hostname || !addr) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;      // Force IPv6 only (struct in6_addr)
    hints.ai_socktype = SOCK_DGRAM;  // UDP (QUIC context)

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        return -1;
    }

    if (!result || !result->ai_addr) {
        if (result) freeaddrinfo(result);
        return -1;
    }

    // Extract struct in6_addr from the sockaddr_in6 structure
    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)result->ai_addr;
    *addr = ipv6->sin6_addr;

    freeaddrinfo(result);
    return 0;
}

int resolve_hostname_ipv4_str(const char *hostname, char *ip_buf, size_t ip_buf_len) {
    if (!hostname || !ip_buf || ip_buf_len < INET_ADDRSTRLEN) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // Force IPv4
    hints.ai_socktype = SOCK_DGRAM;  // UDP

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
       if (status == EAI_SYSTEM) {
            LOG_ERROR("getaddrinfo system error for '%s': %s", hostname, strerror(errno));
        } else {
            LOG_ERROR("getaddrinfo failed for '%s': %s", hostname, gai_strerror(status));
        }
        return -1;
    }

    if (!result) {
        LOG_ERROR("getaddrinfo returned success for '%s', but result list is NULL", hostname);
        return -1;
    }

    if (!result->ai_addr) {
        LOG_ERROR("getaddrinfo returned valid result structure for '%s', but ai_addr pointer is NULL", hostname);
        freeaddrinfo(result);
        return -1;
    }

    struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;

    if (inet_ntop(AF_INET, &(ipv4->sin_addr), ip_buf, (socklen_t)ip_buf_len) == NULL) {
        LOG_ERROR("inet_ntop failed for '%s': %s (buffer size: %zu)", 
                  hostname, 
                  strerror(errno), 
                  ip_buf_len);
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

int resolve_hostname_ipv6_str(const char *hostname, char *ip_buf, size_t ip_buf_len) {
    if (!hostname || !ip_buf || ip_buf_len < INET6_ADDRSTRLEN) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;      // Force IPv6
    hints.ai_socktype = SOCK_DGRAM;  // UDP

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0) {
        return -1;
    }

    if (!result || !result->ai_addr) {
        if (result) freeaddrinfo(result);
        return -1;
    }

    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)result->ai_addr;

    // Convert network binary address to presentation string safely
    if (inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip_buf, (socklen_t)ip_buf_len) == NULL) {
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

int resolve_hostname(const char *hostname, struct sockaddr_storage *addr) {
    if (!hostname || !addr) {
        return -1;
    }

    struct addrinfo hints;
    struct addrinfo *result = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     // Allow IPv4 (AF_INET) or IPv6 (AF_INET6)
    hints.ai_socktype = SOCK_DGRAM;  // UDP (QUIC context)

    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status != 0 || !result || !result->ai_addr) {
        if (result) freeaddrinfo(result);
        return -1;
    }

    // Zero out the output storage struct
    memset(addr, 0, sizeof(struct sockaddr_storage));

    void *addr_ptr = NULL;
    sa_family_t family = result->ai_family;

    if (family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)result->ai_addr;
        memcpy(addr, ipv4, sizeof(struct sockaddr_in));
        addr_ptr = &(ipv4->sin_addr);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)result->ai_addr;
        memcpy(addr, ipv6, sizeof(struct sockaddr_in6));
        addr_ptr = &(ipv6->sin6_addr);
    } else {
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);
    return 0;
}

int sockaddr_to_str(const struct sockaddr_storage *addr, char *ip_buf, size_t ip_buf_len) {
    if (!addr || !ip_buf || ip_buf_len < INET6_ADDRSTRLEN) {
        return -1;
    }

    const void *addr_ptr = NULL;

    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)addr;
        addr_ptr = &(ipv4->sin_addr);
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)addr;
        addr_ptr = &(ipv6->sin6_addr);
    } else {
        return -1; // Unsupported address family
    }

    if (inet_ntop(addr->ss_family, addr_ptr, ip_buf, (socklen_t)ip_buf_len) == NULL) {
        return -1;
    }

    return 0;
}