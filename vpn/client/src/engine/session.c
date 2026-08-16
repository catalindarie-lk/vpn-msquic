
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
        free(session);
        return NULL;
    }

    snprintf(
        session->server_ip_str, 
        sizeof(session->server_ip_str), 
        "%s", 
        ip_str);

    session->server_port = config->server_port;

    assert(state_sync_init(&session->tun_state, TUN_CLOSED) == 0);

    assert(state_sync_init(&session->con_state, SESSION_DISCONNECTED) == 0);

    assert(state_sync_init(&session->stream_state, STREAM_CLOSED) == 0);

    session->shutdown_fd = eventfd(0, EFD_NONBLOCK);

    session->vpn_packet_pool = (pool_t*)pool_init(sizeof(pkt_data_t), 0);
    assert(session->vpn_packet_pool);

    session->pool_pkt_data_recv = (pool_t*)pool_init(sizeof(pkt_data_t), 0);
    assert(session->pool_pkt_data_recv);
    
    session->queue_pkt_data_recv = (queue_t*)queue_init(32 * 1024 * 1024);
    assert(session->queue_pkt_data_recv);

    LOG_DEBUG("Connecting to server... | %s:%u", session->server_ip_str, session->server_port);

    return session;
}






