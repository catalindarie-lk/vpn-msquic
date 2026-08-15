#ifndef TUN_DRIVER_H
#define TUN_DRIVER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef INET_CIDRSTRLEN
#define INET_CIDRSTRLEN (INET_ADDRSTRLEN + 4)
#endif

typedef struct tun_iface_t tun_iface_t;

typedef struct sys_priv_data_t {

    struct {
        const char* sysctl;
        const char* ip;
        const char* resolvectl;
        const char* iptables;
        const char* iptables_restore;
        const char* nft;
    }bin_path;

} sys_priv_data_t;


#ifdef __cplusplus
}
#endif

#endif