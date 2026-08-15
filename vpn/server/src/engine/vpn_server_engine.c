
#include "msquic.h"
#include "pool.h"
#include "queue.h"
#include "quic.h"
#include "session.h"
#include "ip_pool.h"
#include "client.h"
#include "net_iface.h"
#include "tun_api.h"
#include "threads.h"

int port = 443;
const char* local_ip = "10.10.10.11";

const char *cert_file = "cert/server.cert";
const char *key_file = "cert/server.key";


const char* tun_ip = "172.18.0.1";
const char* tun_netmask = "255.255.0.0";

void vpn_engine_cleanup(void *vpn_engine_ctx) {

    session_t *session = (session_t*)vpn_engine_ctx;
    if (!session) return;

    if (session->wan) {
        free(session->wan);
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

    pool_destroy(session->pool_pkt_data_recv);
    pool_destroy(session->pool_pkt_data_send);
    queue_destroy(session->queue_pkt_data_recv);

    ip_pool_destroy(session->ip_pool);
    pool_destroy(session->client_pool);

    if(session->tun) {
        tun_flush_routes(session->tun);
        tun_clear_dns(session->tun);
        tun_rules_clear(session->tun);
        iptables_reset(session->tun);
        tun_ip_forwarding(session->tun, false);
        tun_destroy(session->tun);
        
        state_sync_destroy(&session->tun_state);
        free(session->tun);
        session->tun = NULL;
    }
    

    _exit(0);

    if (session->MsQuic) {
        MsQuicShutdown(session->MsQuic);
    }

    

    free(session);
    session = NULL;
    
    LOG_DEBUG("Finished cleanup");
 
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
            return -ECANCELED;
        }
    } else {
        return -ECANCELED;
    }

    net_iface_t* wan = (net_iface_t* )malloc(sizeof(net_iface_t));
    if (!wan) {
        return ENOMEM;
    }

    wan->ifindex = route_info.ifindex;
    memcpy(wan->ifname, route_info.ifname, IFNAMSIZ);
    wan->gateway = route_info.gateway;
    wan->ip = addr_info.ip;
    memcpy(wan->ip_str, addr_info.ip_str, INET_ADDRSTRLEN);
    wan->ip_str[INET_ADDRSTRLEN - 1] = '\0';
    wan->mask = addr_info.mask;

    session->wan = wan;

    return 0;
}

int setup_tun_interface(session_t* session, const char* ip, const char* netmask, const char* wan_ifname) {
    if (!session || !ip || !netmask || !wan_ifname) {
        return EXIT_FAILURE;
    }

    tun_iface_t* tun = tun_create(TUN_BACKEND_NETLINK_SERVER);
    if (!tun) {
        return EXIT_FAILURE;
    }

    if (tun_open(tun) != 0) {
        goto cleanup;
    }

    if (tun_set_addr(tun, ip, netmask) != 0) {
        goto cleanup;
    }

    if (tun_set_mtu(tun, 1380) != 0) {
        goto cleanup;
    }

    if (tun_set_up(tun) != 0) {
        goto cleanup;
    }

    tun_clear_dns(tun);
    if (tun_set_dns(tun, "1.1.1.1", "8.8.8.8") != 0) {
        goto cleanup;
    }

    char net_cidr[20] = {0};    
    if (tun_get_net_cidr(tun, net_cidr, sizeof(net_cidr)) != 0) {
        goto cleanup;
    }

    // tun_flush_routes(tun);
    tun_rules_clear(tun);

    if (tun_add_route(tun, net_cidr) != 0) {
        goto cleanup;
    }

    if (tun_ip_forwarding(tun, true) != 0) {
        goto cleanup;
    }

    if (tun_server_rules_add(tun, wan_ifname) != 0) {
        goto cleanup;
    }


    if (tun_start(tun) != 0) {
        goto cleanup;
    }

    session->tun = tun;
    state_sync_set(&session->tun_state,  TUN_READY);
    return EXIT_SUCCESS;

cleanup:
    // Rollback system rules
    fprintf(stderr, "\n -------- ROLLING BACK -------- \n\n");
    uint64_t flags = 0;
    tun_get_flags(tun, &flags);

    // Reverse strictly in opposite order of application
    tun_rules_clear(tun);
    tun_ip_forwarding(tun, false);
    tun_clear_dns(tun);
    tun_set_down(tun);
    
    tun_destroy(tun);
    return EXIT_FAILURE;
}

int setup_msquic(session_t *session) {
    SERVER_QUIC_CONTEXT* MsQuic = MsQuicCreate();
    if (!MsQuic) return -1;
    
    if (MsQuicRegister(
        MsQuic, 
        "msquic server app name", 
        QUIC_EXECUTION_PROFILE_LOW_LATENCY) != 0) return -1;

    if (MsQuicConfigLocalAddr(
        MsQuic, 
        local_ip, 
        port) != 0) return -1;

    if (MsQuicConfigCredentials(
        MsQuic, 
        cert_file, 
        key_file, 
        NULL) != 0) return -1;

    if (MsQuicConfigParameters(
        MsQuic, 
        "h3") != 0) return -1;

    if (MsQuicListenerStart(MsQuic, session) != 0) return -1;
    session->MsQuic = MsQuic;
    return 0;
}

int setup_ip_pool_manager(session_t* session) {

    if (!session) {
        return -EINVAL;
    }

    uint64_t flags = 0;
    if (tun_get_flags(session->tun, &flags) != 0) {
        return -EINVAL;
    }

    if (!state_sync_check(&session->tun_state, TUN_READY)) {
        return -ENOTCONN;
    }

    ip_pool_t* ip_pool = ip_pool_create(session->tun);
    if (!ip_pool) {
        session->ip_pool = NULL;
        return -ENOMEM;
    }

    session->ip_pool = ip_pool;
    return 0;
}

int init_client_manager(session_t* session, size_t count) {

    client_t** client_list = malloc(sizeof(client_t*) * count);
    if (!client_list) {
        return ENOMEM;
    }
    memset(client_list, 0, sizeof(client_t*) * count);

    for (int i = 0; i < count; i++) {
        client_list[i] = NULL;
    }

    pthread_mutex_init(&session->client_list_lock, NULL);
    
    session->client_list = client_list;

    pool_t *client_pool = pool_init(sizeof(client_t), count);
    if (!client_pool) {
        pool_destroy(client_pool);
        free(client_list);
        return ENOMEM;
    }
    session->client_pool = client_pool;

    return EXIT_SUCCESS;

}

int start_threads(session_t *session) {

    session->running_pkt_data_send = true;
    if (pthread_create(
        &session->thread_pkt_data_send, 
        NULL, 
        thread_pkt_data_send, 
        session) != 0) return -1;
    
    session->running_pkt_data_recv = true;
    if (pthread_create(
        &session->thread_pkt_data_recv, 
        NULL, 
        thread_pkt_data_recv, 
        session) != 0) return -1;
    
    return 0;

}

void *vpn_engine_start()
{
    session_t* session = create_session();
    if (!session) goto err;

    if (detect_default_wan(session) != 0) goto err;
    
    if (setup_tun_interface(
        session, 
        tun_ip, 
        tun_netmask, 
        session->wan->ifname) != 0) goto err;

    if (setup_ip_pool_manager(session) != 0) goto err;

    if (init_client_manager(
        session, 
        session->ip_pool->max_clients) != 0) goto err;

    if (setup_msquic(session) != 0) goto err;

    if (start_threads(session) != 0) goto err;


    LOG_DEBUG("Server VPN Engine successfully started");
    return (void*)session;

err:
    LOG_ERROR("Server VPN Engine errors detected");
    vpn_engine_cleanup(session);
    return NULL;
}