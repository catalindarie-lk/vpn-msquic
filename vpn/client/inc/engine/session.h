#ifndef SESSION_H
#define SESSION_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdbool.h>

// #include "msquic.h"

#include "app_config.h"
#include "pool.h"
#include "queue.h"
#include "state_sync.h"
#include "tun_api.h"
#include "net_iface.h"

// typedef struct stream_t stream_t;
// typedef struct connection_t connection_t;
typedef struct session_t session_t;
typedef struct CLIENT_QUIC_CONTEXT CLIENT_QUIC_CONTEXT;
typedef struct vpn_config_t vpn_config_t;

typedef enum {
    TUN_CLOSED = 0,
    TUN_READY,
    TUN_FAIL
} tun_state_t;

typedef enum {
    SESSION_CONNECTING = 1,
    SESSION_CONNECTED,
    SESSION_DISCONNECTED
} connection_state_t;

typedef enum {
    STREAM_OPENING = 1,
    STREAM_OPEN,
    STREAM_CLOSED
} stream_state_t;

typedef struct session_t {
    CLIENT_QUIC_CONTEXT* MsQuic;

    char server_ip_str[INET_ADDRSTRLEN];
    uint16_t server_port;

    pool_t *pool_pkt_data_send;

    int shutdown_fd;


    pool_t *pool_pkt_data_recv;
    queue_t *queue_pkt_data_recv;

    net_iface_t* wan;
    tun_iface_t* tun;
    state_sync_t tun_state;

    state_sync_t con_state;
    state_sync_t stream_state;

    pthread_t thread_pkt_data_send;
    bool running_pkt_data_send;

    pthread_t thread_pkt_data_recv;
    bool running_pkt_data_recv;

}session_t;

session_t* session_create(vpn_config_t *config);





#endif // SESSION_H