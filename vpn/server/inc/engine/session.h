#ifndef SESSION_H
#define SESSION_H

#include "pool.h"
#include "queue.h"
#include "tun_api.h"
#include "net_iface.h"
#include "ip_pool.h"
#include "state_sync.h"
// #include "quic.h"

#include <netinet/in.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct client_t client_t;
typedef struct stream_t stream_t;
typedef struct SERVER_QUIC_CONTEXT SERVER_QUIC_CONTEXT;

typedef enum {
    TUN_CLOSED = 0,
    TUN_READY,
    TUN_FAIL
} tun_state_t;

typedef struct session_t {
    // MsQuic Core Engine & Configs

    SERVER_QUIC_CONTEXT *MsQuic;

    // TUN Device & Routing
    tun_iface_t* tun;
    state_sync_t tun_state;
    int shutdown_fd;
    net_iface_t* wan;

    // Concurrency & Memory
    pthread_t thread_pkt_data_send;
    bool running_pkt_data_send;
    pool_t *pool_pkt_data_send;

    pthread_t thread_pkt_data_recv;
    bool running_pkt_data_recv;
    pool_t *pool_pkt_data_recv;
    queue_t *queue_pkt_data_recv;
    
    pool_t *client_pool;
    ip_pool_t* ip_pool;

    // Active Connections
    atomic_uint_fast64_t client_cnt;

    client_t **client_list;
    pthread_mutex_t client_list_lock;

    // pthread_mutex_t conn_lock;
} session_t;

session_t* create_session();

#ifdef __cplusplus
}
#endif

#endif