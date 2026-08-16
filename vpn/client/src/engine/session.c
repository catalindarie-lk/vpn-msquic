
/* 1. Standard C Library Headers */
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/eventfd.h>

/* 2. Internal Project Headers */
#include "pkt_data.h"
#include "session.h"
#include "state_sync.h"
#include "app_config.h"
#include "domain.h"


session_t* session_create(vpn_config_t* config)
{
    session_t* session = (session_t* )malloc(sizeof(session_t));
    if (!session) return NULL;
    memset(session, 0, sizeof(session_t));

    char ip_str[INET_ADDRSTRLEN];
    if (resolve_hostname_ipv4_str(
        config->server_hostname, 
        ip_str, 
        sizeof(ip_str)) != 0) 
    {
        goto err;
    }

    snprintf(
        session->server_ip_str, 
        sizeof(session->server_ip_str), 
        "%s", 
        ip_str);

    session->server_port = config->server_port;

    if (state_sync_init(&session->tun_state, TUN_CLOSED) != 0) goto err;

    if (state_sync_init(&session->con_state, SESSION_DISCONNECTED) != 0) goto err;

    if (state_sync_init(&session->stream_state, STREAM_CLOSED) != 0) goto err;

    session->shutdown_fd = eventfd(0, EFD_NONBLOCK);

    session->pool_pkt_data_send = (pool_t*)pool_init(sizeof(pkt_data_t), 0);
    if (!session->pool_pkt_data_send) goto err;

    session->pool_pkt_data_recv = (pool_t*)pool_init(sizeof(pkt_data_t), 0);
    if (!session->pool_pkt_data_recv) goto err;

    session->queue_pkt_data_recv = (queue_t*)queue_init(64 * 1024 * 1024);
    if (!session->queue_pkt_data_recv) goto err;

    LOG_DEBUG("Connecting to server... | %s:%u", session->server_ip_str, session->server_port);

    return session;

err:
    state_sync_destroy(&session->tun_state);
    state_sync_destroy(&session->con_state);
    state_sync_destroy(&session->stream_state);
    pool_destroy(session->pool_pkt_data_send);
    pool_destroy(session->pool_pkt_data_recv);
    queue_destroy(session->queue_pkt_data_recv);
    return NULL;   
}






