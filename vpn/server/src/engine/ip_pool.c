
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "errno.h"

#include "log.h"
#include "ip_pool.h"
#include "utils.h"
#include "tun_api.h"

ip_pool_t* ip_pool_create(tun_iface_t *tun) {
    
    if (!tun) return NULL;

    ip_pool_t *pool = calloc(1, sizeof(ip_pool_t));
    if (!pool) return NULL;

    tun_get_ip(tun, &pool->server_ip);
    tun_get_mask(tun, &pool->netmask);
    tun_get_net(tun, &pool->net_addr);
  
    // Convert to host byte order for integer math & capacity calculation
    uint32_t net_host = ntohl(pool->net_addr.s_addr);
    uint32_t mask_host = ntohl(pool->netmask.s_addr);
    uint32_t server_host = ntohl(pool->server_ip.s_addr);

    if(!validate_mask(&pool->netmask)) {
        LOG_ERROR("Invalid netmask");
        free(pool);
        return NULL;
    }

    // Number of total IP addresses in this subnet (e.g. 256 for a 255.255.255.0 mask)
    
    pool->max_clients = ~mask_host + 1;

    // Allocate pool entry array dynamically based on subnet capacity
    pool->ip_entry = calloc(pool->max_clients, sizeof(ip_entry_t));
    if (!pool->ip_entry) {
        free(pool);
        return NULL;
    }

    // Populate all pool slots using Host Byte Order arithmetic
    for (uint32_t i = 0; i < pool->max_clients; i++) {
        uint32_t current_host_ip = net_host + i;
        
        // Convert back to Network Byte Order for socket/protocol structs
        pool->ip_entry[i].ip.s_addr = htonl(current_host_ip);

        // Convert to string into the CORRECT array element [i]
        inet_ntop(AF_INET, &pool->ip_entry[i].ip, 
                  pool->ip_entry[i].ip_str, sizeof(pool->ip_entry[i].ip_str));

        pool->ip_entry[i].used = false;
        pool->ip_entry[i].client = NULL;

        // Automatically mark Network (.0), Broadcast (.255), and Server IP as USED
        if (i == 0 || i == (pool->max_clients - 1) || current_host_ip == server_host) {
            pool->ip_entry[i].used = true;
        }
    }

    pthread_mutex_init(&pool->lock, NULL);

    return pool;
}

void ip_pool_destroy(ip_pool_t *pool) {
    if (!pool) return;
    pthread_mutex_destroy(&pool->lock);
    free(pool->ip_entry);
    free(pool);
}

ip_entry_t* ip_acquire(ip_pool_t *pool, client_t *client) {
    if (!pool || !client) return NULL;

    pthread_mutex_lock(&pool->lock);

    // Search through the pool array starting from the last allocation index
    for (uint32_t i = 0; i < pool->max_clients; i++) {
        uint32_t idx = (pool->next_idx + i) % pool->max_clients;
        // uint32_t idx = i;

        if (!pool->ip_entry[idx].used) {
            pool->ip_entry[idx].used = true;
            pool->ip_entry[idx].client = client;

            // Advance round-robin cursor for the next checkout request
            pool->next_idx = (idx + 1) % pool->max_clients;

            pthread_mutex_unlock(&pool->lock);
            return &pool->ip_entry[idx];
        }
    }

    pthread_mutex_unlock(&pool->lock);
    return NULL; // Subnet capacity exhausted!
}

int ip_release(ip_pool_t *pool, ip_entry_t *ip_entry) {
    if (!pool) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    if (!ip_entry) {
        LOG_ERROR("Trying to release ip for invalid entry pointer");
        return -EINVAL;
    }
    pthread_mutex_lock(&pool->lock);

    // Reset entry state
    LOG_DEBUG("Releasing IP [%s]", ip_entry->ip_str);
    ip_entry->used = false;
    ip_entry->client = NULL;

    pthread_mutex_unlock(&pool->lock);
    return 0;
}

client_t* ip_client_search(ip_pool_t *pool, struct in_addr* ip) {
    if (!pool) return NULL;

    uint32_t net_ntoh = ntohl(pool->net_addr.s_addr);
    uint32_t ip_ntoh = ntohl(ip->s_addr);

    // Subnet boundary validation check
    if (ip_ntoh < net_ntoh || ip_ntoh >= (net_ntoh + pool->max_clients)) {
        return NULL; // Target IP is outside TUN subnet
    }

    // Direct O(1) array index offset
    uint32_t idx = ip_ntoh - net_ntoh;

    pthread_mutex_lock(&pool->lock);

    client_t *client = NULL;
    if (pool->ip_entry[idx].used && pool->ip_entry[idx].ip.s_addr == ip->s_addr) {
        client = pool->ip_entry[idx].client;
    }

    pthread_mutex_unlock(&pool->lock);

    return client;
}

