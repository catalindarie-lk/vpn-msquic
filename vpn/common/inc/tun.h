#ifndef TUN_H
#define TUN_H

#include "tun_api.h"

#include <stdint.h>
#include <stdbool.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>


// Operational Vtable Interface for Network Operations
typedef struct tun_api_table_t {
    // Link & Route Mgmt
    int (*tun_open)(tun_iface_t* tun);
    int (*tun_set_address)(tun_iface_t *tun, const char* ip, const char* mask);
    int (*tun_set_mtu)(tun_iface_t *tun, const uint16_t mtu);
    int (*tun_set_up)(tun_iface_t *tun);
    int (*tun_set_down)(tun_iface_t *tun);
    int (*tun_add_route)(tun_iface_t *tun, const char *cidr);
    int (*tun_flush_routes)(tun_iface_t *tun);

    // DNS Mgmt
    int (*tun_set_dns)(tun_iface_t *tun, const char *dns1, const char *dns2);
    int (*tun_clear_dns)(tun_iface_t *tun);

    // NAT & Forwarding
    int (*tun_ip_forwarding)(tun_iface_t *tun, bool enable);
    
    int (*tun_server_rules_add)(tun_iface_t *tun, const char *wan_if);
    int (*tun_client_rules_add)(tun_iface_t *tun, const char *wan_if);

    int (*tun_rules_clear)(tun_iface_t *tun);

    int (*iptables_reset)(tun_iface_t *tun);
    int (*tun_cleanup)(tun_iface_t* tun);

} tun_api_table_t;

// Main TUN Handle structure
typedef struct tun_iface_t {
    int tun_fd;
    uint64_t sts_flags;
    char ifname[IFNAMSIZ];
    struct in_addr ip;
    struct in_addr mask;
    uint8_t prefix;
    struct in_addr gw;
    struct in_addr net;
    struct in_addr dns1;
    struct in_addr dns2;
    uint16_t mtu;
       
    // Engine Pointer
    uint8_t api_type;
    const tun_api_table_t *api;
    void *priv_data; // Storage for backend-specific data (e.g., netlink sockets)
} tun_iface_t;

#endif