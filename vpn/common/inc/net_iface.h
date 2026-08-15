/**
 * @file network_if.h
 * @brief Network interface detection and Netlink routing query interfaces.
 */

#ifndef NETWORK_IF_H
#define NETWORK_IF_H

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Buffer size allocated for Netlink socket messages.
 */
#define NETLINK_BUF_SIZE 8192

/**
 * @brief Holds routing table information retrieved via Netlink.
 */
typedef struct netlink_route_info_t {
    int ifindex;            /**< Interface index associated with route. */
    char ifname[IFNAMSIZ];  /**< Interface device name (e.g., "eth0"). */
    struct in_addr gateway; /**< Gateway IP address in network byte order. */
    uint32_t metric;        /**< Route metric priority value. */
} netlink_route_info_t;

/**
 * @brief Holds network address and subnet properties for an interface.
 */
typedef struct netlink_addr_info_t {
    struct in_addr ip;           /**< IP address in network byte order. */
    char ip_str[INET_ADDRSTRLEN];/**< Null-terminated IPv4 string. */
    struct in_addr mask;         /**< Subnet mask in network byte order. */
    struct in_addr bcast;        /**< Broadcast IP in network byte order. */
    uint8_t prefixlen;           /**< Subnet prefix length (e.g., 24). */
} netlink_addr_info_t;

/**
 * @brief Holds link-layer hardware attributes for an interface.
 */
typedef struct netlink_link_info_t {
    uint32_t mtu;         /**< Maximum Transmission Unit in bytes. */
    unsigned char mac[6]; /**< Hardware MAC address (6 octets). */
} netlink_link_info_t;

/**
 * @brief Aggregated operational snapshot of a network interface.
 */
typedef struct net_iface_t {
    int ifindex;                  /**< System interface index. */
    char ifname[IFNAMSIZ];        /**< Interface name string. */
    struct in_addr ip;            /**< Assigned IPv4 address. */
    char ip_str[INET_ADDRSTRLEN]; /**< Presentation format IPv4 string. */
    struct in_addr mask;          /**< Assigned subnet mask. */
    struct in_addr gateway;       /**< Default gateway IPv4 address. */
} net_iface_t;

/**
 * @brief Checks whether the network interface is operational.
 *
 * @param[in] ifname Interface name string (e.g., "eth0", "wlan0").
 * @return true if the link is active and operational, false otherwise.
 */
bool is_link_online(const char *ifname);

/**
 * @brief Determines if the interface matching index is a loopback device.
 *
 * @param[in] ifindex System index of the network interface.
 * @return true if loopback, false otherwise.
 */
bool netlink_is_loopback(int ifindex);

/**
 * @brief Determines if the interface is a Point-to-Point device.
 *
 * @param[in] ifindex System index of the network interface.
 * @return true if point-to-point (e.g., TUN/TAP), false otherwise.
 */
bool netlink_is_pointtopoint(int ifindex);

/**
 * @brief Queries the default routing table via Netlink for an address family.
 *
 * @param[in] af Address family (e.g., AF_INET for IPv4).
 * @param[out] route_info Output structure for route attributes.
 * @return 0 on success, or a negative error code on failure.
 */
int get_netlink_route_info(uint8_t af,
                            netlink_route_info_t *route_info);

/**
 * @brief Retrieves address details for an interface index via Netlink.
 *
 * @param[in] af Address family identifier (e.g., AF_INET).
 * @param[in] ifindex Target network interface index.
 * @param[out] addr_info Output structure for address details.
 * @return 0 on success, or a negative error code on failure.
 */
int get_netlink_addr_info(int8_t af,
                           int ifindex,
                           netlink_addr_info_t *addr_info);

/**
 * @brief Retrieves link properties (MTU, MAC) for an interface index.
 *
 * @param[in] ifindex Target network interface index.
 * @param[out] link_info Output structure for link properties.
 * @return 0 on success, or a negative error code on failure.
 */
int get_netlink_link_info(int ifindex,
                           netlink_link_info_t *link_info);

/**
 * @brief Prints formatted Netlink diagnostic info to stdout.
 *
 * @param[in] route_info Pointer to populated route information.
 * @param[in] addr_info Pointer to populated address information.
 * @param[in] link_info Pointer to populated link-layer information.
 */
void print_netlink_iface_info(const netlink_route_info_t *route_info,
                              const netlink_addr_info_t *addr_info,
                              const netlink_link_info_t *link_info);

#endif /* NETWORK_IF_H */