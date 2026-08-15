
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>

#include "tun_api.h"
#include "tun.h"
#include "log.h"
#include "utils.h"

typedef struct tun_api_table_t tun_api_table_t;

// Declarations of internal drivers
extern const tun_api_table_t api_table_netlink_client;
extern const tun_api_table_t api_table_netlink_server;

static const tun_api_table_t* get_sys_api(tun_api_table_type_t api_type) {
    switch (api_type) {
        case TUN_BACKEND_NETLINK_CLIENT:
            return &api_table_netlink_client;
        case TUN_BACKEND_NETLINK_SERVER:
            return &api_table_netlink_server;
        case TUN_BACKEND_IOCTL:
            // Not implemented
            return NULL;
        default:
            return NULL;
    }
}

/* Helper macro to perform driver checks and dispatch vtable calls safely */
#define DISPATCH_SYS_API(tun, func_name, ...)                        \
    do {                                                             \
        if (!(tun)) {                                                \
            LOG_ERROR("Invalid parameter: NULL handle");             \
            return -EINVAL;                                          \
        }                                                            \
        if (!(tun)->api) {                                           \
            LOG_ERROR("Driver not initialized");                     \
            return -ENODEV;                                          \
        }                                                            \
        if (!(tun)->api->func_name) {                                \
            LOG_ERROR("Unsupported operational method: " #func_name);\
            return -ENOSYS;                                          \
        }                                                            \
    } while (0)

/* Helper macro to safely stringify and copy member fields to destination buffers */
static inline int safe_strcpy(char *dest, size_t dest_len, const char *src, size_t src_max_len) {
    if (!dest || !src || dest_len == 0) return -EINVAL;

    size_t actual_len = strnlen(src, src_max_len);
    if (actual_len >= dest_len) {
        LOG_ERROR("Buffer too small for string operation");
        return -ENOBUFS;
    }

    memcpy(dest, src, actual_len);
    dest[actual_len] = '\0';
    return 0;
}

//------------------------------------------------------------------------------------------------
// LIFECYCLE MANAGEMENT
//------------------------------------------------------------------------------------------------

tun_iface_t* tun_create(tun_api_table_type_t api_type) {
        
    tun_iface_t *tun = calloc(1, sizeof(tun_iface_t));
    if (!tun) {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    tun->api_type = api_type;

    const tun_api_table_t *api = get_sys_api(tun->api_type);
    if (!api) {
        LOG_ERROR("Invalid or unsupported API driver type");
        free(tun);
        return NULL;
    }

    tun->api = api;
    tun->tun_fd = -1;
    tun->sts_flags = TUN_STATE_NONE;
    return tun;
}
int tun_start(tun_iface_t *tun) {
    if (!tun) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    if (!tun->api) {
        LOG_ERROR("Driver not initialized");
        return -ENODEV;
    }
    if ((tun->sts_flags & TUN_STATE_READY) != TUN_STATE_READY) {
        LOG_ERROR("TUN device not in ready state. Can not start");
        return -ENODEV;
    }
    LOG_DEBUG("TUN device started successfully");
    return 0;
}
int tun_get_flags(const tun_iface_t *tun, uint64_t *out_flags) {
    if (!tun || !out_flags) return -EINVAL;
    *out_flags = tun->sts_flags;
    return 0;
}
int tun_destroy(tun_iface_t *tun) {
    if (!tun) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    if (tun->api) {
        tun->api->tun_cleanup(tun);
    }
    return 0;
}

//------------------------------------------------------------------------------------------------
// ENGINE WRAPPERS
//------------------------------------------------------------------------------------------------

int tun_open(tun_iface_t* tun) {
    DISPATCH_SYS_API(tun, tun_open, tun, NULL, 0);
    int ret = tun->api->tun_open(tun);
    if (ret == 0) {
        tun->sts_flags |= TUN_STATE_OPEN;
    }
    return ret;
}

int tun_set_addr(tun_iface_t *tun, const char* ip, const char* mask) {
    DISPATCH_SYS_API(tun, tun_set_address, tun, ip, mask);
    int ret = tun->api->tun_set_address(tun, ip, mask);
    if (ret == 0) {
        tun->sts_flags |= (TUN_STATE_IP_SET | TUN_STATE_MASK_SET);
    }
    return ret;
}

int tun_set_mtu(tun_iface_t *tun, uint16_t mtu) {
    DISPATCH_SYS_API(tun, tun_set_mtu, tun, mtu);
    int ret = tun->api->tun_set_mtu(tun, mtu);
    if (ret == 0) {
        tun->sts_flags |= TUN_STATE_MTU_SET;
    }
    return ret;
}

int tun_set_up(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, tun_set_up, tun);
    int ret = tun->api->tun_set_up(tun);
    if (ret == 0) {
        tun->sts_flags |= TUN_STATE_UP;
    }
    return ret;
}

int tun_set_down(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, tun_set_down, tun);
    int ret = tun->api->tun_set_down(tun);
    if (ret == 0) {
        tun->sts_flags &= ~TUN_STATE_UP;
    }
    return ret;
}

int tun_set_dns(tun_iface_t *tun, const char* dns1, const char* dns2) {
    DISPATCH_SYS_API(tun, tun_set_dns, tun, dns1, dns2);
    int ret = tun->api->tun_set_dns(tun, dns1, dns2);
    if (ret == 0) {
        tun->sts_flags |= TUN_STATE_DNS_SET;
    }
    return ret;
}

int tun_clear_dns(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, tun_clear_dns, tun);
    int ret = tun->api->tun_clear_dns(tun);
    if (ret == 0) {
        tun->sts_flags &= ~TUN_STATE_DNS_SET;
    }
    return ret;
}

int tun_add_route(tun_iface_t *tun, const char* cidr) {
    DISPATCH_SYS_API(tun, tun_add_route, tun, cidr);
    return tun->api->tun_add_route(tun, cidr);
}

int tun_flush_routes(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, tun_flush_routes, tun);
    return tun->api->tun_flush_routes(tun);
}

int tun_ip_forwarding(tun_iface_t *tun, bool enable) {
    DISPATCH_SYS_API(tun, tun_ip_forwarding, tun, enable);
    int ret = tun->api->tun_ip_forwarding(tun, enable);
    return ret;
}

int tun_server_rules_add(tun_iface_t *tun, const char *wan_if) {
    DISPATCH_SYS_API(tun, tun_server_rules_add, tun, wan_if);
    int ret = tun->api->tun_server_rules_add(tun, wan_if);
    return ret;
}

int tun_client_rules_add(tun_iface_t *tun, const char *wan_if) {
    DISPATCH_SYS_API(tun, tun_client_rules_add, tun, wan_if);
    int ret = tun->api->tun_client_rules_add(tun, wan_if);
    return ret;
}

int tun_rules_clear(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, tun_rules_clear, tun);
    int ret = tun->api->tun_rules_clear(tun);
    return ret;
}

int iptables_reset(tun_iface_t *tun) {
    DISPATCH_SYS_API(tun, iptables_reset, tun);
    int ret = tun->api->iptables_reset(tun);
    return ret;
}

//------------------------------------------------------------------------------------------------
// HELPERS
//------------------------------------------------------------------------------------------------

int tun_get_fd(const tun_iface_t *tun, int *out_fd) {
    if (!tun || !out_fd) return -EINVAL;
    *out_fd = tun->tun_fd;
    return 0;
}

int tun_get_ifname(const tun_iface_t *tun, char* buf, size_t buf_len) {
    if (!tun) return -EINVAL;
    return safe_strcpy(buf, buf_len, tun->ifname, sizeof(tun->ifname));
}

int tun_get_mtu(const tun_iface_t *tun, uint16_t *out_mtu) {
    if (!tun || !out_mtu) return -EINVAL;
    *out_mtu = tun->mtu;
    return 0;
}

int tun_get_ip(const tun_iface_t *tun, struct in_addr *out) {
    if (!tun || !out) return -EINVAL;
    *out = tun->ip;
    return 0;
}

int tun_get_dns1(const tun_iface_t *tun, struct in_addr *out) {
    if (!tun || !out) return -EINVAL;
    *out = tun->dns1;
    return 0;
}

int tun_get_dns2(const tun_iface_t *tun, struct in_addr *out) {
    if (!tun || !out) return -EINVAL;
    *out = tun->dns2;
    return 0;
}

int tun_get_mask(const tun_iface_t *tun, struct in_addr *out) {
    if (!tun || !out) return -EINVAL;
    *out = tun->mask;
    return 0;
}

int tun_get_net(const tun_iface_t *tun, struct in_addr *out) {
    if (!tun || !out) return -EINVAL;
    // Calculate network address on the fly (IP & MASK)
    out->s_addr = tun->ip.s_addr & tun->mask.s_addr;
    return 0;
}

int tun_get_ip_str(const tun_iface_t *tun, char *buf, size_t buf_len) {
    if (!tun) return -EINVAL;
    return in_addr_to_str(&tun->ip, buf, buf_len);
}

int tun_get_mask_str(const tun_iface_t *tun, char *buf, size_t buf_len) {
    if (!tun) return -EINVAL;
    return in_addr_to_str(&tun->mask, buf, buf_len);
}

int tun_get_net_str(const tun_iface_t *tun, char *buf, size_t buf_len) {
    if (!tun) return -EINVAL;
    
    struct in_addr net_addr;
    net_addr.s_addr = tun->ip.s_addr & tun->mask.s_addr;
    return in_addr_to_str(&net_addr, buf, buf_len);
}

int tun_get_ip_cidr(const tun_iface_t *tun, char *buf, size_t buf_len) {
    if (!tun) return -EINVAL;

    int8_t prefix = mask_to_prefix(&tun->mask);
    if (prefix < 0) return (int)prefix;

    return in_addr_to_cidr(&tun->ip, &tun->mask, buf, buf_len);
}

int tun_get_net_cidr(const tun_iface_t *tun, char *buf, size_t buf_len) {
    if (!tun) return -EINVAL;

    struct in_addr net_addr;
    net_addr.s_addr = tun->ip.s_addr & tun->mask.s_addr;
    return in_addr_to_cidr(&net_addr, &tun->mask, buf, buf_len);
}