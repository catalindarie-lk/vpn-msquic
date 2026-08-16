
/* 2. C Standard Library Headers */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/* 3. System, POSIX, and Linux Kernel Headers */
#include <error.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>

/* 4. Third-Party Library Headers */
#include "msquic.h"

/* 5. Internal Project Headers */
#include "log.h"
#include "net_iface.h"
#include "pkt_ctrl.h"
#include "pool.h"
#include "queue.h"
#include "quic.h"
#include "session.h"
#include "state_sync.h"
#include "tun_api.h"
#include "threads.h"

#include "app_config.h"


void vpn_engine_cleanup(session_t *session) {

    if (!session) {
        return;
    }

    if (session->running_pkt_data_send) {
        session->running_pkt_data_send = false;
        
        uint64_t signal_val = 1;
        write(session->shutdown_fd, &signal_val, sizeof(signal_val));

        pthread_join(session->thread_pkt_data_send, NULL);
        close(session->shutdown_fd);

    }

    if (session->running_pkt_data_recv) {
        session->running_pkt_data_recv = false;
        queue_wait_push(session->queue_pkt_data_recv, NULL);
        pthread_join(session->thread_pkt_data_recv, NULL);
    }

    if(session->tun) {
        tun_flush_routes(session->tun);
        tun_clear_dns(session->tun);
        tun_rules_clear(session->tun);
        tun_destroy(session->tun);
        state_sync_destroy(&session->tun_state);
        free(session->tun);
        session->tun = NULL;
    }

    if (session->MsQuic) {
        MsQuicShutdown(session->MsQuic);
        session->MsQuic = NULL;
    }

    if (session->wan) {
        free(session->wan);
        session->wan = NULL;
    }

    state_sync_destroy(&session->con_state);
    state_sync_destroy(&session->stream_state);
    pool_destroy(session->pool_pkt_data_send);
    pool_destroy(session->pool_pkt_data_recv);
    queue_destroy(session->queue_pkt_data_recv);

    LOG_DEBUG("Finished cleanup");
    
    free(session);
    session = NULL;
    
    return;
}

int detect_default_wan(session_t* session) {
    
    netlink_route_info_t route_info;
    netlink_addr_info_t addr_info;
    netlink_link_info_t link_info;

    if (get_netlink_route_info(AF_INET, &route_info) == 0) {
        if (get_netlink_addr_info(AF_INET, route_info.ifindex, &addr_info) == 0 &&
            get_netlink_link_info(route_info.ifindex, &link_info) == 0) {
            
            print_netlink_iface_info(&route_info, &addr_info, &link_info);
        } else {
            LOG_ERROR("Wan interface detect error");
            return -ECANCELED;
        }
    } else {
        LOG_ERROR("Wan interface detect error");
        return -ECANCELED;
    }

    net_iface_t* wan = (net_iface_t* )malloc(sizeof(net_iface_t));
    if (!wan) {
        LOG_ERROR("Wan interface handle create error");
        return -ENOMEM;
    }

    wan->ifindex = route_info.ifindex;
    memcpy(wan->ifname, route_info.ifname, IFNAMSIZ);
    wan->gateway = route_info.gateway;
    wan->ip = addr_info.ip;
    memcpy(wan->ip_str, addr_info.ip_str, INET_ADDRSTRLEN);
    wan->ip_str[INET_ADDRSTRLEN - 1] = '\0';
    wan->mask = addr_info.mask;

    session->wan = wan;
    LOG_DEBUG("Wan interface handle created successfully");

    return 0;
}

int setup_msquic(session_t *session) {
    CLIENT_QUIC_CONTEXT *MsQuic = MsQuicCreate();
    if (!MsQuic) return -1;
    session->MsQuic = MsQuic;
    
    if (MsQuicRegister(
        MsQuic, 
        "msquic client app name", 
        QUIC_EXECUTION_PROFILE_LOW_LATENCY) != 0) return -1;
    
    if (MsQuicConfigAddr(
        MsQuic, 
        session->wan->ip_str, 
        session->server_ip_str, 
        session->server_port) != 0) return -1;

    if (MsQuicConfigParameters(MsQuic, "h3") != 0) return -1;
    if (MsQuicConfigCredentials(MsQuic) != 0) return -1;

    if (MsQuicConnectionStart(MsQuic, session) != 0) return -1;
    if (MsQuicStreamStart(MsQuic, session) != 0) return -1;

    LOG_DEBUG("MsQuic setup successfull");
    return 0;
}

int request_virtip(session_t *session) {
   // SEND REQ FOR VPN IP
    pkt_ctrl_t* pkt = pkt_ctrl_create_config_req(
        0, 
        AF_INET, 
        "quic vpn client"
    );
    if (MsQuicStreamSend(session->MsQuic, (void*)pkt, sizeof(pkt_ctrl_t)) != 0) return -1;

    if(state_sync_wait_ms(&session->tun_state, TUN_READY, 5000) != 0) {
        return -1;
    }

    return 0;

}

int start_threads(session_t *session) {
    session->running_pkt_data_send = true;
    if (pthread_create(
        &session->thread_pkt_data_send, 
        NULL, 
        thread_pkt_data_send,
        (void* )session) != 0) return -1;
   
    session->running_pkt_data_recv = true;
    if (pthread_create(
        &session->thread_pkt_data_recv, 
        NULL, thread_pkt_data_recv, 
        (void* )session) != 0) return -1;

    return 0;
}


void *vpn_engine_start(vpn_config_t *config)
{
    session_t* session = session_create(config);
    if (!session) goto err;
    
    if (detect_default_wan(session) != 0) goto err;

    if (setup_msquic(session) != 0) goto err;

    if (request_virtip(session) != 0) goto err;

    if (start_threads(session) != 0) goto err;

    LOG_DEBUG("Server VPN Engine successfully started");

    return(session);

err:    
    LOG_ERROR("Server VPN Engine errors detected");
    vpn_engine_cleanup(session);
    return NULL;
}
