

#include "tun.h"
#include "tun_api.h"

#include "tun_driver.h"
#include "tun_api.h"
#include "utils.h"
#include "log.h"

// #include <asm-generic/errno-base.h>
// #include <asm-generic/errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <errno.h>


static int syt_server_rules_add_nft(tun_iface_t *tun, const char *wan_if);
static int syt_client_rules_add_nft(tun_iface_t *tun, const char *wan_if);
static int sys_rules_clear_nft(tun_iface_t *tun);


static int sys_iptables_reset_nft(tun_iface_t *tun);

//===================================================================================================
//  INTERNAL
//===================================================================================================

static inline int init_priv_data(sys_priv_data_t* priv) {

    const char *bin_path = NULL;

    //==================================================
    //          Locate the sysctl utility binary
    //==================================================
    char *const sysctl_paths[] = {
        "/sbin/sysctl",
        "/usr/sbin/sysctl",
        "/bin/sysctl",
        "/usr/bin/sysctl",
        NULL
    };

    bin_path = find_binary(sysctl_paths);
    if (!bin_path) {
        LOG_ERROR("Could not locate sysctl binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.sysctl = bin_path;

    //==================================================
    //          Locate ip utility binary
    //==================================================
    char *const ip_paths[] = { 
        "/sbin/ip", 
        "/usr/sbin/ip", 
        "/bin/ip", 
        "/usr/bin/ip", 
        NULL };

    bin_path = find_binary(ip_paths);

    if (!bin_path) {
        LOG_ERROR("Could not locate ip binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.ip = bin_path;
    
    //==================================================
    //          Locate iptables utility binary
    //==================================================
    char *const iptables_paths[] = {
        "/sbin/iptables",
        "/usr/sbin/iptables",
        "/bin/iptables",
        "/usr/bin/iptables",
        NULL
    };

    bin_path = find_binary(iptables_paths);
    if (!bin_path) {
        LOG_ERROR("Could not locate iptables binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.iptables = bin_path;

    //==================================================
    //          Locate iptables utility binary
    //==================================================
    char *const iptables_restore_paths[] = {
        "/sbin/iptables-restore",
        "/usr/sbin/iptables-restore",
        "/bin/iptables-restore",
        "/usr/bin/iptables-restore",
        NULL
    };

    bin_path = find_binary(iptables_restore_paths);
    if (!bin_path) {
        LOG_ERROR("Could not locate iptables binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.iptables_restore = bin_path;

    //==================================================
    //          Locate iptables utility binary
    //==================================================
    char* const resolvectl_paths[] = {
        "/usr/bin/resolvectl",
        "/bin/resolvectl",
        NULL
    };

    bin_path = find_binary(resolvectl_paths);
    if (!bin_path) {
        LOG_ERROR("Could not locate resolvectl binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.resolvectl = bin_path;

    //==================================================
    //          Locate nft utility binary
    //==================================================
    char* const nft_paths[] = {
        "/usr/sbin/nft",
        "/sbin/nft",
        "/usr/bin/nft",
        "/usr/local/sbin/nft",
        NULL
    };

    bin_path = find_binary(nft_paths);
    if (!bin_path) {
        LOG_ERROR("Could not locate nft binary in standard paths");
        return -ENOENT;
    }
    priv->bin_path.nft = bin_path;

    LOG_DEBUG("Initialized private data success");

    return EXIT_SUCCESS;
}

//===================================================================================================
//  API
//===================================================================================================

static int sys_tun_open(tun_iface_t* tun) {

    int err = 0;
    int ret = 0;

    if (!tun) {
        LOG_ERROR("Invalid argumets");
        return -EINVAL;
    }

    const char *name_prefix = "tun";
    
    struct ifreq ifr;
    tun->tun_fd = open("/dev/net/tun", O_RDWR);
    if (tun->tun_fd < 0) {
        err = -errno;
        LOG_ERROR("Open /dev/net/tun failed: errno: %d", errno);
        return err;
    }

    /* Flags:
     * IFF_TUN   - IP level device (packet encapsulation without Ethernet headers)
     * IFF_NO_PI - Do not supply 4-byte extra packet information header
     */
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    snprintf(ifr.ifr_name, IFNAMSIZ, "%.10s%%d", name_prefix);

    // Allocate the network interface in the kernel
    if (ioctl(tun->tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to allocate interface: errno: %d", errno);
        close(tun->tun_fd);
        return err;
    }
    memcpy(tun->ifname, ifr.ifr_name, IFNAMSIZ);
    LOG_DEBUG("Created tunneling interface: %s", tun->ifname);

    //==================================================================================
    sys_priv_data_t *priv = (sys_priv_data_t* )malloc(sizeof(sys_priv_data_t));
    if (!priv) {
        LOG_ERROR("Failed to allocate memory for private data");
        return -ENOMEM;
    }
    memset(priv, 0, sizeof(sys_priv_data_t));

    ret = init_priv_data(priv);
    if (ret != 0) return ret;

    tun->priv_data = (void* )priv;

    return 0;
}

static int sys_tun_set_address(tun_iface_t* tun, const char* ip, const char* mask) {
    
    int err = 0;
    int ret = 0;

    // Validate pointer sanity
    if (!tun || !ip || !mask) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    //===============================================================================
    // Convert ip from string to in_addr
    //===============================================================================
    ret = inet_pton(AF_INET, ip, &tun->ip);
    if (ret <= 0) {
        if (ret == 0) {
            err = -EINVAL;
            LOG_ERROR("Invalid IPv4 address format: %s", ip);
        } else {
            err = -errno;
            LOG_ERROR("inet_pton() fail");
        }
        return err;
    }
    LOG_DEBUG("Interface: %s | IPv4 set to %s", tun->ifname, ip);

    //===============================================================================
    // Convert netmask from string to in_addr
    //===============================================================================
    ret = inet_pton(AF_INET, mask, &tun->mask);
    if (ret <= 0) {
        if (ret == 0) {
            err = -EINVAL;
            LOG_ERROR("Invalid IPv4 address format: %s", mask);
        } else {
            err = -errno;
            LOG_ERROR("inet_pton() fail");
        }
        return err;
    }

    // Verify netmask is logically valid (contiguous bitmask)
    if (!validate_mask(&tun->mask)) {
        LOG_ERROR("Invalid mask: %s", mask);
        return -EINVAL;
    }

    tun->prefix = mask_to_prefix(&tun->mask);
    if (tun->prefix < 0) {
        LOG_ERROR("Invalid mask: %s", mask);
        return -EINVAL;
    }
    LOG_DEBUG("Interface: %s | Netmask set to %s", tun->ifname, mask);


    //===============================================================================
    // Calculate network address (bitwise AND ip and netmask)
    //===============================================================================

    tun->net.s_addr = tun->ip.s_addr & tun->mask.s_addr;

    //===================================================================================
    // Set ip and netmask with ioctl()
    //===================================================================================
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        err = -errno;
        LOG_ERROR("socket() failure");
        return err;
    }

    if (tun->ifname[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        close(sock);
        return -EINVAL;
    }

    struct ifreq ifr;
    
    // Set IP
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, tun->ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr = tun->ip;

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to set ip - interface %s : errno %d", tun->ifname, errno);
        close(sock);
        return err;
    }

    // Set subnet mask
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, tun->ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    struct sockaddr_in *mask_addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    mask_addr->sin_family = AF_INET;
    mask_addr->sin_addr = tun->mask;

    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        LOG_ERROR("Failed to set mask - interface %s : errno %d", tun->ifname, errno);
        close(sock);
        return err;
    }

    close(sock);
    return 0;
}

static int sys_tun_set_mtu(tun_iface_t* tun, const uint16_t mtu) {
    int err = 0;

    // Validate pointer and MTU bounds sanity
    if (!tun || tun->ifname[0] == '\0' || mtu < 256 || mtu > 1380) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        err = -errno;
        LOG_ERROR("Failed to create control socket for interface %s: errno: %d", 
                tun->ifname, errno);
        return err;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, tun->ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // Assign MTU
    tun->mtu = mtu;
    ifr.ifr_mtu = (int)tun->mtu;

    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to set MTU %u on interface %s: errno: %d", 
                tun->mtu, tun->ifname, errno);
        close(sock);
        return err;
    }

    close(sock);

    LOG_DEBUG("Interface: %s | MTU set to %u", tun->ifname, tun->mtu);
    return 0;
}

static int sys_tun_set_up(tun_iface_t* tun) {
    int err = 0;

    if (!tun || tun->ifname[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        err = -errno;
        LOG_ERROR("Failed to create control socket interface %s : errno: %d", 
                tun->ifname, errno);
        return err;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, tun->ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to fetch flags interface %s : errno: %d", 
                tun->ifname, errno);
        close(sock);
        return err;
    }

    // Set flags to bring interface UP and RUNNING
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to bring up interface %s : errno: %d", 
                tun->ifname, errno);
        close(sock);
        return err;
    }

    close(sock);

    LOG_DEBUG("Interface: %s | Interface brought UP successfully (flags: 0x%04x)", 
            tun->ifname, ifr.ifr_flags);
    return 0;
}

static int sys_tun_set_down(tun_iface_t *tun) {
    int err = 0;

    if (!tun || tun->ifname[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        err = -errno;
        LOG_ERROR("Failed to create control socket interface %s : errno: %d", 
                tun->ifname, errno);
        return err;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, tun->ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to fetch flags interface %s : errno: %d", 
                tun->ifname, errno);
        close(sock);
        return err;
    }

    // Clear flags to bring interface DOWN
    ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        err = -errno;
        LOG_ERROR("Failed to bring down interface %s : errno: %d", 
                tun->ifname, errno);
        close(sock);
        return err;
    }

    close(sock);

    LOG_DEBUG("Interface: %s | Interface brought DOWN (flags: 0x%04x)", tun->ifname, ifr.ifr_flags);
    return 0;
}

static int sys_tun_set_dns(tun_iface_t *tun, const char *dns1_str, const char *dns2_str) {
    
    int err = 0;
    int ret = 0;

    if (!tun || !dns1_str || !dns2_str || 
        tun->ifname[0] == '\0' || dns1_str[0] == '\0' || dns2_str[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (!priv || !priv->bin_path.resolvectl) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    ret = inet_pton(AF_INET, dns1_str, &tun->dns1);
    if (ret <= 0) {
        if (ret == 0) {
            err = -EINVAL;
            LOG_ERROR("Invalid IPv4 address format for DNS1: %s", dns1_str);
        } else {
            err = -errno;
            LOG_ERROR("inet_pton() fail for DNS1");
        }
        return err;
    }

    ret = inet_pton(AF_INET, dns2_str, &tun->dns2);
    if (ret <= 0) {
        if (ret == 0) {
            err = -EINVAL;
            LOG_ERROR("Invalid IPv4 address format for DNS2: %s", dns2_str);
        } else {
            err = -errno;
            LOG_ERROR("inet_pton() fail for DNS2");
        }
        return err;
    }

    const char *bin_path = priv->bin_path.resolvectl;

    {
        char *const command[] = {
            (char *)bin_path, 
            "dns", 
            tun->ifname, 
            (char*)dns1_str, 
            (char*)dns2_str, 
            NULL
        };
        ret = run_command(bin_path, command);
        if (ret != 0) {
            LOG_ERROR("Failed to set DNS servers via resolvectl on interface %s", tun->ifname);
            return ret;
        } 
    }
    LOG_DEBUG("Interface: %s | DNS set to %s, %s", tun->ifname, dns1_str, dns2_str);

    // 5. Set routing domain (~ routes all queries to this interface)
    {
        char *const command[] = {
            (char *)bin_path, 
            "domain", 
            tun->ifname, 
            "~", 
            NULL
        };
        ret = run_command(bin_path, command);
        if (ret != 0) {
            LOG_ERROR("Failed to set default DNS domain routing via resolvectl on interface %s", tun->ifname);
            return ret;
        }
    }
    LOG_DEBUG("Interface: %s | Default DNS domain routing configured (~)", tun->ifname);

    return 0;
}

static int sys_tun_add_route(tun_iface_t *tun, const char *cidr) {
    int ret = 0;

    // Validate pointer sanity and non-empty inputs
    if (!tun || !cidr || tun->ifname[0] == '\0' || cidr[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (!priv || !priv->bin_path.ip) {
        LOG_ERROR("Invalid private data or ip binary path");
        return -EINVAL;
    }
    const char *bin_path = priv->bin_path.ip;

    // ip route replace <cidr> dev <ifname>
    char *const cmd[] = {
        (char *)bin_path, 
        "route", 
        "replace", 
        (char *)cidr, 
        "dev", 
        tun->ifname, 
        NULL
    };
    
    ret = run_command(bin_path, cmd);
    if (ret != 0) {
        LOG_ERROR("Failed to [ip route replace %s dev %s]", cidr, tun->ifname);
        return ret;
    } 

    LOG_DEBUG("Interface: %s | Route added/replaced: %s", tun->ifname, cidr);

    return 0;
}

static int sys_tun_flush_routes(tun_iface_t *tun) {
    int ret = 0;

    if (!tun || tun->ifname[0] == '\0') {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (!priv || !priv->bin_path.ip) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    const char *bin_path = priv->bin_path.ip;

    // ip route flush dev <ifname> table all
    char *const cmd[] = {
        (char *)bin_path, 
        "route",
        "flush", 
        "dev", 
        tun->ifname, 
        "table",
        "all",
        NULL
    };

    ret = run_command(bin_path, cmd);

    if (ret != 0) {
        LOG_WARNING("Failed to [ip route flush dev %s table all]", tun->ifname);
    } else {
        LOG_DEBUG("Interface: %s | Flushed all routes on device", tun->ifname);
    }   

    return 0;
}


static int sys_tun_clear_dns(tun_iface_t *tun) {
    
    int ret = 0;
    int wrn = 0;

    // Input parameters validation
    if (!tun) {
        LOG_ERROR("Invalid parameter: tun pointer is NULL");
        return -EINVAL;
    }

    if (tun->ifname[0] == '\0') {
        LOG_ERROR("Invalid parameter: tun->ifname is empty");
        return -EINVAL;
    }

    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (!priv) {
        LOG_ERROR("Invalid parameter: tun->priv_data is NULL");
        return -EINVAL;
    }

    const char *bin_path = priv->bin_path.resolvectl;
    if (!bin_path) {
        LOG_ERROR("Invalid parameter: resolvectl bin_path is NULL");
        return -EINVAL;
    }

    /* =========================================================================
     * RESOLVECTL DNS & DOMAIN CLEAR
     * ========================================================================= */

    // Revert domain routing rule (resolvectl domain <ifname> "")
    {
        char *const command[] = {
            (char *)bin_path, 
            "domain", 
            tun->ifname, 
            "", 
            NULL
        };
        ret = run_command(bin_path, command);
        if (ret != 0) {
            wrn = ret;
            LOG_WARNING("Failed to revert domain routing on %s (%d)", tun->ifname, ret);
        }
    }

    // Flush/revert DNS servers assigned to the interface (resolvectl dns <ifname> "")
    {
        char *const command[] = {
            (char *)bin_path, 
            "dns", 
            tun->ifname, 
            "", 
            NULL
        };
        ret = run_command(bin_path, command);
        if (ret != 0) {
            wrn = ret;
            LOG_WARNING("Failed to clear DNS configuration on %s (%d)", tun->ifname, ret);
        }
    }

    if (wrn == 0) {
        LOG_DEBUG("Interface: %s | Reverted domain routing and cleared DNS configuration", tun->ifname);
    }

    return 0;
}

static int sys_tun_cleanup(tun_iface_t *tun) {
    
    int ret = 0;
    int wrn = 0;

    // Input parameters validation
    if (!tun) {
        LOG_ERROR("Invalid parameter: tun pointer is NULL");
        return -EINVAL;
    }

    /* =========================================================================
     * BRING INTERFACE DOWN (ioctl)
     * ========================================================================= */
    if (tun->ifname[0] != '\0') {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            LOG_ERROR("Failed to create socket for interface down ioctl: errno: %d", errno);
            ret = -errno;
        } else {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            snprintf(ifr.ifr_name, IFNAMSIZ, "%s", tun->ifname);

            if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
                LOG_ERROR("Failed to get interface flags for %s: errno: %d", 
                    tun->ifname, errno);
                ret = -errno;
            } else {
                ifr.ifr_flags &= ~(IFF_UP | IFF_RUNNING);
                if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
                    LOG_ERROR("Failed to set interface %s to DOWN: errno: %d", 
                        tun->ifname, errno);
                    ret = -errno;
                } else {
                    LOG_DEBUG("Interface: %s | Interface set to DOWN", 
                        tun->ifname);
                }
            }
            close(sock);
        }
    } else {
        wrn = ret;
        LOG_WARNING("Interface name is empty; skipping ioctl down operations");
    }

    /* =========================================================================
     * CLOSE TUN DEVICE DESCRIPTOR
     * ========================================================================= */
    if (tun->tun_fd >= 0) {
        int target_fd = tun->tun_fd;
        if (close(tun->tun_fd) < 0) {
            LOG_ERROR("Failed to close TUN file descriptor (fd=%d): errno: %d", 
                target_fd, errno);
            ret = -errno;
        } else {
            LOG_DEBUG("Interface: %s | Closed TUN file descriptor (fd=%d)", 
                    tun->ifname[0] != '\0' ? tun->ifname : "unknown", target_fd);
        }
        tun->tun_fd = -1;
    }

    /* =========================================================================
     * FREE PRIVATE SYSTEM DATA
     * ========================================================================= */
    
    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (priv) {
        memset(priv, 0, sizeof(sys_priv_data_t));
        free(priv);
        tun->priv_data = NULL;
    }

    if (ret != 0) {
        LOG_ERROR("Interface teardown completed with errors (%d)", ret);
        return ret;
    }

    if (wrn == 0) {
        LOG_DEBUG("Interface: %s | Interface destroyed cleanly", tun->ifname);
    }

    return 0;
}

static int server_sys_tun_ip_forwarding(tun_iface_t *tun, const bool enable) {
    int ret = 0;

    // Validate pointer sanity
    if (!tun) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    sys_priv_data_t *priv = (sys_priv_data_t *)tun->priv_data;
    if (!priv || !priv->bin_path.sysctl) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    const char *bin_path = priv->bin_path.sysctl;

    char *const set_on[] = {
        (char *)bin_path, 
        "-w",
        "net.ipv4.ip_forward=1",
        NULL
    };

    char *const set_off[] = {
        (char *)bin_path, 
        "-w",
        "net.ipv4.ip_forward=0",
        NULL
    };

    char *const *cmd = enable ? set_on : set_off;

    ret = run_command(bin_path, cmd);

    if (ret != 0) {
        LOG_ERROR("Failed to %s IPv4 forwarding via sysctl", enable ? "enable" : "disable");
        return ret;
    }

    LOG_DEBUG("Interface: %s | IPv4 forwarding %s successfully via sysctl", 
            tun->ifname[0] != '\0' ? tun->ifname : "global", 
            enable ? "enabled" : "disabled");

    return 0;
}

// Bind operations to the sys_tools driver instance
const tun_api_table_t api_table_netlink_server = {
    .tun_open = sys_tun_open,
    .tun_set_address = sys_tun_set_address,
    .tun_set_mtu = sys_tun_set_mtu, // Add wrapper similar to sys_set_ip_and_mask
    .tun_set_up = sys_tun_set_up,
    .tun_set_down = sys_tun_set_down,
    .tun_add_route = sys_tun_add_route,
    .tun_flush_routes = sys_tun_flush_routes,
    .tun_set_dns = sys_tun_set_dns,
    .tun_clear_dns = sys_tun_clear_dns,
    .tun_ip_forwarding = server_sys_tun_ip_forwarding,
    .tun_server_rules_add = syt_server_rules_add_nft,
    .tun_client_rules_add = NULL,
    .tun_rules_clear = sys_rules_clear_nft,
    .tun_cleanup = sys_tun_cleanup,
    .iptables_reset = sys_iptables_reset_nft,
};

const tun_api_table_t api_table_netlink_client = {
    .tun_open = sys_tun_open,
    .tun_set_address = sys_tun_set_address,
    .tun_set_mtu = sys_tun_set_mtu,
    .tun_set_up = sys_tun_set_up,
    .tun_set_down = sys_tun_set_down,
    .tun_add_route = sys_tun_add_route,
    .tun_flush_routes = sys_tun_flush_routes,
    .tun_set_dns = sys_tun_set_dns,
    .tun_clear_dns = sys_tun_clear_dns,
    .tun_ip_forwarding = NULL,
    .tun_server_rules_add = NULL,
    .tun_client_rules_add = NULL,
    .tun_rules_clear = sys_rules_clear_nft,
    .tun_cleanup = sys_tun_cleanup,
    .iptables_reset = NULL,
};





// #include <spawn.h>
// #include <unistd.h>
// #include <sys/wait.h>
// #include <string.h>
// #include <errno.h>

static int run_nft_script(const char *nft_bin, const char *ruleset, char *err_buf, size_t err_len) {
    if (!nft_bin || !ruleset) return -EINVAL;

    int in_pipe[2], err_pipe[2];
    if (pipe(in_pipe) < 0) return -errno;
    if (pipe(err_pipe) < 0) {
        close(in_pipe[0]);
        close(in_pipe[1]);
        return -errno;
    }

    // Set up file actions for posix_spawn
    posix_spawn_file_actions_t actions;
    int res = posix_spawn_file_actions_init(&actions);
    if (res != 0) {
        close(in_pipe[0]);  close(in_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -res;
    }

    // 1. Redirect standard streams in child process
    posix_spawn_file_actions_adddup2(&actions, in_pipe[0], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&actions, err_pipe[1], STDERR_FILENO);

    // 2. Close pipe handles inside child process after redirecting
    posix_spawn_file_actions_addclose(&actions, in_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, in_pipe[1]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[0]);
    posix_spawn_file_actions_addclose(&actions, err_pipe[1]);

    char *const args[] = { (char *)nft_bin, "-f", "-", NULL };
    char *const envp[] = { "LC_ALL=C", NULL };

    pid_t pid;
    res = posix_spawn(&pid, nft_bin, &actions, NULL, args, envp);

    // Clean up spawn actions structure
    posix_spawn_file_actions_destroy(&actions);

    if (res != 0) {
        close(in_pipe[0]);  close(in_pipe[1]);
        close(err_pipe[0]); close(err_pipe[1]);
        return -res;
    }

    // Parent Process: Close child-side pipe handles
    close(in_pipe[0]);
    close(err_pipe[1]);

    // Write ruleset to nft's stdin and signal EOF by closing write end
    write(in_pipe[1], ruleset, strlen(ruleset));
    close(in_pipe[1]);

    // Read stderr from child
    if (err_buf && err_len > 0) {
        ssize_t n = read(err_pipe[0], err_buf, err_len - 1);
        if (n > 0) {
            err_buf[n] = '\0';
        } else {
            err_buf[0] = '\0';
        }
    }
    close(err_pipe[0]);

    // Wait for child process exit
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        return -errno;
    }

    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -ECHILD;
}

static int syt_server_rules_add_nft(tun_iface_t *tun, const char *wan_if) {
    char cidr[INET_CIDRSTRLEN] = {0};
    if (in_addr_to_cidr(&tun->ip, &tun->mask, cidr, sizeof(cidr)) != 0) {
        return -EINVAL;
    }

    char ruleset[1024];
    char err_buf[256] = {0};

    /* Fully self-contained table statement: creates if missing, flushes if existing */
    snprintf(ruleset, sizeof(ruleset),
        "table ip vpn_%s {\n"
        "    chain forward {\n"
        "        type filter hook forward priority filter; policy accept;\n"
        "        iifname \"%s\" oifname \"%s\" accept\n"
        "        iifname \"%s\" oifname \"%s\" ct state established,related accept\n"
        "    }\n"
        "    chain postrouting {\n"
        "        type nat hook postrouting priority srcnat; policy accept;\n"
        "        ip saddr %s oifname \"%s\" masquerade\n"
        "    }\n"
        "}\n",
        tun->ifname,
        tun->ifname, wan_if,
        wan_if, tun->ifname,
        cidr, wan_if);

    sys_priv_data_t *priv = (sys_priv_data_t* )tun->priv_data;
    if (!priv) {
        LOG_ERROR("TUN private data not initialized");
        return -ECANCELED;
    }

    int ret = run_nft_script(priv->bin_path.nft, ruleset, err_buf, sizeof(err_buf));
    if (ret != 0) {
        LOG_ERROR("Failed to apply nftables rules: %s", err_buf[0] ? err_buf : "Unknown error");
        return ret;
    }

    LOG_DEBUG("Interface: %s | Applied atomic nftables NAT rules", tun->ifname);
    return 0;
}


static int syt_client_rules_add_nft(tun_iface_t *tun, const char *wan_if) {
    return 0;
}

static int sys_rules_clear_nft(tun_iface_t *tun) {
    if (!tun) {
        LOG_ERROR("Invalid parameter: tun is NULL");
        return -EINVAL;
    }

    const char *tun_if = tun->ifname;
    if (!tun_if || tun_if[0] == '\0') {
        LOG_ERROR("Invalid parameter: tun->ifname is NULL or empty");
        return -EINVAL;
    }

    /* Target the table created during setup */
    char ruleset[128];
    snprintf(ruleset, sizeof(ruleset), "destroy table ip vpn_%s\n", tun_if);

    sys_priv_data_t *priv = (sys_priv_data_t* )tun->priv_data;
    if (!priv) {
        LOG_ERROR("TUN private data not initialized");
        return -ECANCELED;
    }

    char err_buf[256] = {0};
    int ret = run_nft_script(priv->bin_path.nft, ruleset, err_buf, sizeof(err_buf));

    if (ret != 0) {
        if (err_buf[0] != '\0') {
            LOG_ERROR("Failed to destroy nftables table vpn_%s: %s",
                      tun_if, err_buf);
        } else {
            LOG_ERROR("Failed to destroy nftables table vpn_%s (code %d)",
                      tun_if, ret);
        }
        return ret;
    }

    LOG_DEBUG("Interface: %s | Successfully destroyed NAT table (vpn_%s)",
              tun_if, tun_if);

    return 0;
}


static int sys_iptables_reset_nft(tun_iface_t *tun) {
    if (!tun) {
        LOG_ERROR("Invalid argument: tun pointer is NULL");
        return -EINVAL;
    }

    /* "flush ruleset" wipes all tables, chains, and rules globally in one transaction */
    const char *ruleset = "flush ruleset\n";

    sys_priv_data_t *priv = (sys_priv_data_t* )tun->priv_data;
    if (!priv) {
        LOG_ERROR("TUN private data not initialized");
        return -ECANCELED;
    }

    char err_buf[256] = {0};
    int ret = run_nft_script(priv->bin_path.nft, ruleset, err_buf, sizeof(err_buf));

    if (ret != 0) {
        if (err_buf[0] != '\0') {
            LOG_ERROR("Failed to flush nftables ruleset: %s", err_buf);
        } else {
            LOG_ERROR("Failed to flush nftables ruleset (code %d)", ret);
        }
        return ret;
    }

    LOG_DEBUG("Reset nftables to clean default state via flush ruleset");
    return 0;
}









// static int run_nft_script(const char* nft_bin, const char *ruleset, char *err_buf, size_t err_len) {
//     int in_pipe[2], err_pipe[2];

//     if (pipe(in_pipe) < 0 || pipe(err_pipe) < 0) return -errno;

//     pid_t pid = fork();
//     if (pid < 0) {
//         close(in_pipe[0]); close(in_pipe[1]);
//         close(err_pipe[0]); close(err_pipe[1]);
//         return -errno;
//     }

//     if (pid == 0) {
//         /* Child Process */
//         dup2(in_pipe[0], STDIN_FILENO);
//         dup2(err_pipe[1], STDERR_FILENO);

//         close(in_pipe[0]); close(in_pipe[1]);
//         close(err_pipe[0]); close(err_pipe[1]);

//         /* Execute nft reading from stdin (-) */
//         char *const args[] = {
//             (char*)nft_bin, 
//             "-f", 
//             "-", 
//             NULL
//         };
//         execv(args[0], args);
//         _exit(127);
//     }

//     /* Parent Process */
//     close(in_pipe[0]);
//     close(err_pipe[1]);

//     /* Write ruleset to nft stdin */
//     write(in_pipe[1], ruleset, strlen(ruleset));
//     close(in_pipe[1]); /* Close STDIN to signal EOF to nft */

//     /* Read stderr errors if any */
//     if (err_buf && err_len > 0) {
//         ssize_t n = read(err_pipe[0], err_buf, err_len - 1);
//         if (n > 0) err_buf[n] = '\0';
//         else err_buf[0] = '\0';
//     }
//     close(err_pipe[0]);

//     int status;
//     waitpid(pid, &status, 0);

//     return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -ECHILD;
// }