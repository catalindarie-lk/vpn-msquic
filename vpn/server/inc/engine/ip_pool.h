#ifndef IP_POOL_H
#define IP_POOL_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "tun_api.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct session_t session_t;
typedef struct client_t client_t;
typedef struct ip_entry_t ip_entry_t;

typedef struct ip_entry_t{
    struct in_addr ip;
    char ip_str[INET_ADDRSTRLEN];
    bool used;
    client_t* client;
} ip_entry_t;

typedef struct ip_pool_t{
    struct in_addr net_addr;
    struct in_addr netmask;
    struct in_addr server_ip;
    
    ip_entry_t* ip_entry;
    size_t max_clients;
    size_t next_idx;
    pthread_mutex_t lock;

} ip_pool_t;


ip_pool_t* ip_pool_create(tun_iface_t *tun) ;
void ip_pool_destroy(ip_pool_t *pool);

ip_entry_t* ip_acquire(ip_pool_t *pool, client_t *client);
int ip_release(ip_pool_t *pool, ip_entry_t *ip_entry);

client_t* ip_client_search(ip_pool_t *pool, struct in_addr* ip);


#ifdef __cplusplus
}
#endif

#endif // IP_POOL_H