#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define NETLINK_BUF_SIZE 8192

typedef struct {
    int ifindex;
    char ifname[IFNAMSIZ];
    struct in_addr gateway;
    uint32_t metric;
} netlink_route_info_t;

typedef struct {
    struct in_addr ip;
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr mask;
    struct in_addr bcast;
    uint8_t prefixlen;
} netlink_addr_info_t;

typedef struct {
    uint32_t mtu;
    unsigned char mac[6];
} netlink_link_info_t;


bool is_link_online(const char *ifname) {
    if (!ifname || ifname[0] == '\0') return false;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        return false;
    }
    close(sock);

    return (ifr.ifr_flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING);
}

bool netlink_is_loopback(int ifindex) {
    if (ifindex <= 0) return true;

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) return false;

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;

    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(nl_fd);
        return false;
    }

    char buf[NETLINK_BUF_SIZE];
    ssize_t len = recv(nl_fd, buf, sizeof(buf), 0);
    close(nl_fd);

    if (len < 0) return false;

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    if (NLMSG_OK(nlh, (size_t)len) && nlh->nlmsg_type == RTM_NEWLINK) {
        struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
        return (ifi->ifi_flags & IFF_LOOPBACK) != 0;
    }

    return false;
}

bool netlink_is_pointtopoint(int ifindex) {
    if (ifindex <= 0) return true;

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) return false;

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;

    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        close(nl_fd);
        return false;
    }

    char buf[NETLINK_BUF_SIZE];
    ssize_t len = recv(nl_fd, buf, sizeof(buf), 0);
    close(nl_fd);

    if (len < 0) return false;

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    if (NLMSG_OK(nlh, (size_t)len) && nlh->nlmsg_type == RTM_NEWLINK) {
        struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
        return (ifi->ifi_flags & (IFF_POINTOPOINT | IFF_NOARP)) != 0;
    }

    return false;
}

int get_netlink_route_info(uint8_t af, netlink_route_info_t *route_info) {
    if (!route_info) return EINVAL;
    if (af != AF_INET) return EAFNOSUPPORT;

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) return errno;

    uint32_t best_metric = UINT32_MAX;
    bool found = false;

    struct {
        struct nlmsghdr nlh;
        struct rtmsg rtm;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_type = RTM_GETROUTE;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.rtm.rtm_family = af;
    req.rtm.rtm_table = RT_TABLE_MAIN;

    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        int err = errno;
        close(nl_fd);
        return err;
    }

    char buffer[NETLINK_BUF_SIZE];
    bool done = false;

    while (!done) {
        ssize_t len = recv(nl_fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            int err = errno;
            close(nl_fd);
            return err;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nlh->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }

            if (nlh->nlmsg_type != RTM_NEWROUTE) 
                continue;

            struct rtmsg *rt = (struct rtmsg *)NLMSG_DATA(nlh);

            if (rt->rtm_family != af || rt->rtm_table != RT_TABLE_MAIN) 
                continue;

            if (rt->rtm_dst_len != 0)
                continue;

            if (rt->rtm_type != RTN_UNICAST || rt->rtm_scope == RT_SCOPE_HOST || rt->rtm_scope == RT_SCOPE_LINK) {
                continue;
            }

            struct rtattr *rta = (struct rtattr *)RTM_RTA(rt);
            int rta_len = RTM_PAYLOAD(nlh);

            char ifname[IFNAMSIZ] = {0};
            int ifindex = 0;
            uint32_t metric = 0;
            bool has_gateway = false;
            bool skip_interface = false;
            struct in_addr gateway = {0};

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                switch (rta->rta_type) {
                    case RTA_OIF:
                        ifindex = *(int *)RTA_DATA(rta);

                        // Fixed switch continue bug: Set flag and break attribute loop
                        if (netlink_is_loopback(ifindex) || netlink_is_pointtopoint(ifindex)) {
                            skip_interface = true;
                            break;
                        }

                        if (if_indextoname(ifindex, ifname) == NULL) {
                            memset(ifname, 0, IFNAMSIZ);
                        }
                        break;
                    case RTA_GATEWAY:
                        gateway = *(struct in_addr *)RTA_DATA(rta);
                        has_gateway = true;
                        break;
                    case RTA_PRIORITY:
                        metric = *(uint32_t *)RTA_DATA(rta);
                        break;
                }
                if (skip_interface) break;
            }

            if (skip_interface) continue;

            if (ifindex > 0 && has_gateway && metric <= best_metric) {
                if (!is_link_online(ifname)) {
                    continue;
                }

                found = true;
                best_metric = metric;

                route_info->ifindex = ifindex;
                route_info->metric = metric;
                route_info->gateway = gateway;
                
                memcpy(route_info->ifname, ifname, IFNAMSIZ);
                route_info->ifname[IFNAMSIZ - 1] = '\0';

                // snprintf(route_info->ifname, sizeof(route_info->ifname), "%s", ifname);
            }
        }
    }

    close(nl_fd);
    return found ? 0 : ENODEV;
}

int get_netlink_addr_info(int8_t af, int ifindex, netlink_addr_info_t *addr_info) {
    if (!addr_info || ifindex <= 0) return EINVAL;
    if (af != AF_INET) return EAFNOSUPPORT;

    memset(addr_info, 0, sizeof(netlink_addr_info_t));

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) return errno;

    struct {
        struct nlmsghdr nlh;
        struct ifaddrmsg ifa;
    } req;
    memset(&req, 0, sizeof(req));
    
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    req.nlh.nlmsg_type = RTM_GETADDR;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifa.ifa_family = af;
    req.ifa.ifa_index = ifindex;

    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        int err = errno;
        close(nl_fd);
        return err;
    }

    char buffer[NETLINK_BUF_SIZE];
    bool found = false;
    bool done = false;

    while (!done) {
        ssize_t len = recv(nl_fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            int err = errno;
            close(nl_fd);
            return err;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        for (; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
            if (nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }

            if (nlh->nlmsg_type != RTM_NEWADDR)
                continue;

            struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);

            if (ifa->ifa_index != (unsigned int)ifindex || ifa->ifa_family != af || ifa->ifa_scope == RT_SCOPE_HOST) {
                continue;
            }

            struct rtattr *rta = IFA_RTA(ifa);
            int rta_len = IFA_PAYLOAD(nlh);

            struct in_addr local_ip = {0};
            struct in_addr bcast_ip = {0};

            for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
                switch (rta->rta_type) {
                    case IFA_LOCAL:
                        local_ip = *(struct in_addr *)RTA_DATA(rta);
                        break;
                    case IFA_ADDRESS:
                        if (local_ip.s_addr == 0) {
                            local_ip = *(struct in_addr *)RTA_DATA(rta);
                        }
                        break;
                    case IFA_BROADCAST:
                        bcast_ip = *(struct in_addr *)RTA_DATA(rta);
                        break;
                }
            }

            if (local_ip.s_addr != 0) {
                addr_info->ip = local_ip;
                addr_info->prefixlen = ifa->ifa_prefixlen;
                inet_ntop(AF_INET, &addr_info->ip, addr_info->ip_str, INET_ADDRSTRLEN);

                if (ifa->ifa_prefixlen > 0 && ifa->ifa_prefixlen <= 32) {
                    uint32_t mask_host = (0xFFFFFFFFu << (32 - ifa->ifa_prefixlen)) & 0xFFFFFFFFu;
                    addr_info->mask.s_addr = htonl(mask_host);
                } else if (ifa->ifa_prefixlen == 0) {
                    addr_info->mask.s_addr = 0;
                }

                if (bcast_ip.s_addr != 0) {
                    addr_info->bcast = bcast_ip;
                } else if (addr_info->mask.s_addr != 0) {
                    addr_info->bcast.s_addr = addr_info->ip.s_addr | ~addr_info->mask.s_addr;
                }

                found = true;
                done = true;
                break;
            }
        }
    }

    close(nl_fd);
    return found ? 0 : ENODEV;
}

int get_netlink_link_info(int ifindex, netlink_link_info_t *link_info) {
    if (!link_info || ifindex <= 0) return EINVAL;

    memset(link_info, 0, sizeof(netlink_link_info_t));

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) return errno;

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_type = RTM_GETLINK;
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_seq = 1;
    req.nlh.nlmsg_pid = getpid();
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = ifindex;

    if (send(nl_fd, &req, req.nlh.nlmsg_len, 0) < 0) {
        int err = errno;
        close(nl_fd);
        return err;
    }

    char buffer[NETLINK_BUF_SIZE];
    ssize_t len = recv(nl_fd, buffer, sizeof(buffer), 0);
    close(nl_fd);

    if (len < 0) return errno;

    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

    if (!NLMSG_OK(nlh, (size_t)len) || nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type != RTM_NEWLINK) {
        return ENODEV;
    }

    struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
    struct rtattr *rta = IFLA_RTA(ifi);
    int rta_len = IFLA_PAYLOAD(nlh);

    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        switch (rta->rta_type) {
            case IFLA_MTU:
                link_info->mtu = *(uint32_t *)RTA_DATA(rta);
                break;

            case IFLA_ADDRESS:
                if (RTA_PAYLOAD(rta) >= 6) {
                    memcpy(link_info->mac, RTA_DATA(rta), 6);
                }
                break;
        }
    }

    return 0;
}

/**
 * Pretty-prints combined netlink interface, address, and route information.
 *
 * @param route_info Pointer to the populated route struct.
 * @param addr_info  Pointer to the populated IP address struct.
 * @param link_info  Pointer to the populated link attributes struct.
 */
void print_netlink_iface_info(const netlink_route_info_t *route_info,
                             const netlink_addr_info_t *addr_info,
                             const netlink_link_info_t *link_info) {
    if (!route_info || !addr_info || !link_info) {
        printf("[!] Invalid or null structure pointer passed to print function.\n");
        return;
    }

    char ip_str[INET_ADDRSTRLEN]    = "0.0.0.0";
    char mask_str[INET_ADDRSTRLEN]  = "0.0.0.0";
    char bcast_str[INET_ADDRSTRLEN] = "0.0.0.0";
    char gw_str[INET_ADDRSTRLEN]    = "0.0.0.0";

    inet_ntop(AF_INET, &addr_info->ip, ip_str, sizeof(ip_str));
    inet_ntop(AF_INET, &addr_info->mask, mask_str, sizeof(mask_str));
    inet_ntop(AF_INET, &addr_info->bcast, bcast_str, sizeof(bcast_str));
    inet_ntop(AF_INET, &route_info->gateway, gw_str, sizeof(gw_str));

    printf("==================================================\n");
    printf(" Network Interface Information\n");
    printf("==================================================\n");
    printf(" Interface     : %s (ifindex: %d)\n", route_info->ifname, route_info->ifindex);
    printf(" MAC Address   : %02X:%02X:%02X:%02X:%02X:%02X\n",
           link_info->mac[0], link_info->mac[1], link_info->mac[2],
           link_info->mac[3], link_info->mac[4], link_info->mac[5]);
    printf(" MTU           : %u\n", link_info->mtu);
    printf("--------------------------------------------------\n");
    printf(" IPv4 Address  : %s/%u\n", ip_str, addr_info->prefixlen);
    printf(" Subnet Mask   : %s\n", mask_str);
    printf(" Broadcast IP  : %s\n", bcast_str);
    printf(" Gateway IP    : %s\n", gw_str);
    printf(" Route Metric  : %u\n", route_info->metric);
    printf("==================================================\n");
}


//===========================================================================================================
// NOT YET TESTED
//===========================================================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <arpa/inet.h>

#define NL_BUF_SIZE 8192

// Open and bind a socket to Netlink routing updates
int open_netlink_event_listener(void) {
    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    // Subscribe to link states, IPv4 addresses, and IPv4 routing changes
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;

    if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(nl_fd);
        return -1;
    }

    return nl_fd;
}

// Parses a Netlink message stream to determine if WAN routing changed
bool process_netlink_event(int nl_fd, int *current_wan_ifindex) {
    char buffer[NL_BUF_SIZE];
    ssize_t len = recv(nl_fd, buffer, sizeof(buffer), 0);
    if (len < 0) {
        if (errno == EAGAIN || errno == EINTR) return false;
        perror("recv");
        return false;
    }

    bool wan_changed = false;
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

    for (; NLMSG_OK(nlh, (size_t)len); nlh = NLMSG_NEXT(nlh, len)) {
        // We care primarily about route updates and link state changes
        if (nlh->nlmsg_type == RTM_NEWROUTE || nlh->nlmsg_type == RTM_DELROUTE) {
            struct rtmsg *rt = (struct rtmsg *)NLMSG_DATA(nlh);

            // Filter for main routing table and IPv4 default routes (dst_len == 0)
            if (rt->rtm_family == AF_INET && 
                rt->rtm_table == RT_TABLE_MAIN && 
                rt->rtm_dst_len == 0) {

                // A default route was added, modified, or removed!
                wan_changed = true;
            }
        } 
        else if (nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK) {
            struct ifinfomsg *ifi = (struct ifinfomsg *)NLMSG_DATA(nlh);
            
            // If the current active WAN interface went DOWN, flag a change
            if (ifi->ifi_index == *current_wan_ifindex) {
                if (!(ifi->ifi_flags & IFF_UP) || !(ifi->ifi_flags & IFF_RUNNING)) {
                    wan_changed = true;
                }
            }
        }
    }

    return wan_changed;
}

// Example WAN monitor loop - this should run in a separate thread in order to listen for events.
void monitor_wan_changes(void) {
    int nl_fd = open_netlink_event_listener();
    if (nl_fd < 0) return;

    netlink_route_info_t current_route = {0};
    netlink_addr_info_t current_addr = {0};
    netlink_link_info_t current_link = {0};

    // Initial query using your existing functions
    if (get_netlink_route_info(AF_INET, &current_route) == 0) {
        get_netlink_addr_info(AF_INET, current_route.ifindex, &current_addr);
        get_netlink_link_info(current_route.ifindex, &current_link);
        print_netlink_iface_info(&current_route, &current_addr, &current_link);
    } else {
        printf("[!] No active WAN interface found at startup.\n");
    }

    printf("\n[*] Listening for network changes...\n");

    while (1) {
        // Blocking wait for events from the kernel
        if (process_netlink_event(nl_fd, &current_route.ifindex)) {
            printf("\n[!] WAN route or interface state event detected! Re-evaluating...\n");

            netlink_route_info_t new_route = {0};
            
            // Query the new best default route
            if (get_netlink_route_info(AF_INET, &new_route) == 0) {
                // Check if the gateway or interface index actually changed
                if (new_route.ifindex != current_route.ifindex ||
                    new_route.gateway.s_addr != current_route.gateway.s_addr) {
                    
                    printf("[+] Active WAN changed from %s (ifindex: %d) -> %s (ifindex: %d)\n",
                           current_route.ifname, current_route.ifindex,
                           new_route.ifname, new_route.ifindex);

                    // Fetch full metrics for the new WAN interface
                    netlink_addr_info_t new_addr = {0};
                    netlink_link_info_t new_link = {0};
                    get_netlink_addr_info(AF_INET, new_route.ifindex, &new_addr);
                    get_netlink_link_info(new_route.ifindex, &new_link);

                    // Update tracked state
                    current_route = new_route;
                    current_addr = new_addr;
                    current_link = new_link;

                    print_netlink_iface_info(&current_route, &current_addr, &current_link);

                    // TODO: Call your re-configuration / failover callbacks here
                }
            } else {
                if (current_route.ifindex != 0) {
                    printf("[-] Primary WAN connection lost entirely!\n");
                    memset(&current_route, 0, sizeof(current_route));
                }
            }
        }
    }

    close(nl_fd);
}