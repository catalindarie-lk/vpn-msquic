/**
 * @file tun_api.h
 * @brief Public API interface for managing TUN network devices and VPN network state.
 *
 * This header exposes handle lifecycle management, device configuration setters,
 * state querying, and getter helpers for underlying TUN interfaces without exposing
 * internal vtables or system implementation details.
 */

#ifndef TUN_API_H
#define TUN_API_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque handle representing a TUN interface instance.
 *
 * External callers manipulate this state handle strictly through the functions
 * declared in this header.
 */
typedef struct tun_iface_t tun_iface_t;

/**
 * @brief Bitmask flags representing the current configuration state of a TUN interface.
 */
typedef enum : uint64_t {
    TUN_STATE_NONE       = 0,            /**< Initial state; no settings applied. */
    TUN_STATE_OPEN       = (1ULL << 0),  /**< Interface allocated/named. */
    TUN_STATE_IP_SET     = (1ULL << 1),  /**< IPv4 address configured. */
    TUN_STATE_MASK_SET   = (1ULL << 2),  /**< Subnet mask configured. */
    TUN_STATE_MTU_SET    = (1ULL << 3),  /**< MTU set. */
    TUN_STATE_UP         = (1ULL << 4),  /**< Interface link state set to UP. */
    TUN_STATE_DNS_SET    = (1ULL << 5),  /**< Primary/Secondary DNS servers configured. */

    /** Aggregate mask representing a fully configured and operational interface. */
    TUN_STATE_READY      = TUN_STATE_OPEN |
                           TUN_STATE_IP_SET |
                           TUN_STATE_MASK_SET |
                           TUN_STATE_MTU_SET |
                           TUN_STATE_UP |
                           TUN_STATE_DNS_SET

    /* ... (1ULL << 63) ... */

} vpn_state_flags_t;

/**
 * @brief System execution backends supported by the driver engine.
 */
typedef enum {
    TUN_BACKEND_NETLINK_CLIENT = 1,  /**< Userspace command utilities (ip, iptables, resolvectl). */
    TUN_BACKEND_NETLINK_SERVER = 2,
    TUN_BACKEND_IOCTL,        /**< Direct Kernel Netlink sockets & nftables API. */
    VPN_CUSTOM                /**< Custom user-defined interface driver. */
} tun_api_table_type_t;

/* ========================================================================= *
 * ALLOCATION & LIFECYCLE MANAGEMENT                                         *
 * ========================================================================= */

/**
 * @brief Allocates and initializes a new TUN handle.
 *
 * @param[in] api_type Backend implementation engine to use.
 * @return Pointer to allocated `tun_iface_t` instance, or `NULL` on failure.
 */
tun_iface_t* tun_create(tun_api_table_type_t api_type);

/**
 * @brief Starts and brings up the TUN interface applying queued configurations.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_start(tun_iface_t *tun);

/**
 * @brief Retrieves the current operational state bitmask of the TUN handle.
 *
 * @param[in]  tun       Pointer to the TUN handle instance.
 * @param[out] out_flags Pointer to populate with the bitmask of `vpn_state_flags_t`.
 * @return `0` on success, or `-EINVAL` if parameters are NULL.
 */
int tun_get_flags(const tun_iface_t *tun, uint64_t *out_flags);

/**
 * @brief Destroys the TUN interface, cleans up assigned routes/NAT, and frees memory.
 *
 * @param[in] tun Pointer to the TUN handle instance to destroy.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_destroy(tun_iface_t *tun);

/* ========================================================================= *
 * CONFIGURATION SETTERS                                                     *
 * ========================================================================= */

/**
 * @brief Opens the underlying `/dev/net/tun` device node.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_open(tun_iface_t* tun);

/**
 * @brief Sets the IPv4 address and netmask for the interface.
 *
 * @param[in] tun  Pointer to the TUN handle instance.
 * @param[in] ip   IPv4 address string (e.g., "10.0.0.1").
 * @param[in] mask Subnet mask string (e.g., "255.255.255.0").
 * @return `0` on success, or a negative error code on failure.
 */
int tun_set_addr(tun_iface_t *tun, const char* ip, const char* mask);

/**
 * @brief Configures the Maximum Transmission Unit (MTU) size.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @param[in] mtu MTU value in bytes (e.g., 1420 or 1500).
 * @return `0` on success, or a negative error code on failure.
 */
int tun_set_mtu(tun_iface_t *tun, uint16_t mtu);

/**
 * @brief Sets the link state of the TUN interface to UP.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_set_up(tun_iface_t *tun);

/**
 * @brief Sets the link state of the TUN interface to DOWN.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_set_down(tun_iface_t *tun);

/**
 * @brief Configures primary and secondary DNS servers for the interface.
 *
 * @param[in] tun  Pointer to the TUN handle instance.
 * @param[in] dns1 Primary DNS address string.
 * @param[in] dns2 Secondary DNS address string (optional, can be NULL).
 * @return `0` on success, or a negative error code on failure.
 */
int tun_set_dns(tun_iface_t *tun, const char* dns1, const char* dns2);

/**
 * @brief Removes registered DNS settings associated with this interface.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_clear_dns(tun_iface_t *tun);

/**
 * @brief Adds a CIDR network route via this TUN interface.
 *
 * @param[in] tun  Pointer to the TUN handle instance.
 * @param[in] cidr Route CIDR string (e.g., "192.168.1.0/24").
 * @return `0` on success, or a negative error code on failure.
 */
int tun_add_route(tun_iface_t *tun, const char* cidr);

/**
 * @brief Flushes all routing table entries associated with this interface.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_flush_routes(tun_iface_t *tun);

/**
 * @brief Enables or disables IPv4 packet forwarding in the OS kernel.
 *
 * @param[in] tun    Pointer to the TUN handle instance.
 * @param[in] enable Set `true` to enable IP forwarding, `false` to disable.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_ip_forwarding(tun_iface_t *tun, bool enable);

/**
 * @brief Configures NAT/Masquerade rules targeting a WAN interface.
 *
 * @param[in] tun    Pointer to the TUN handle instance.
 * @param[in] wan_if Interface name handling outgoing internet connectivity (e.g., "eth0", "wlan0").
 * @return `0` on success, or a negative error code on failure.
 */
int tun_server_rules_add(tun_iface_t *tun, const char *wan_if);

/**
 * @brief
 *
 * @param[in] tun    Pointer to the TUN handle instance.
 * @param[in] wan_if Interface name handling outgoing internet connectivity (e.g., "eth0", "wlan0").
 * @return `0` on success, or a negative error code on failure.
 */
int tun_client_rules_add(tun_iface_t *tun, const char *wan_if, const char *server_ip, uint16_t server_port);


/**
 * @brief Disables NAT masquerading rules configured for this interface.
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_rules_clear(tun_iface_t *tun);


/**
 * @brief Cleares all rules in iptables (reset to default state).
 *
 * @param[in] tun Pointer to the TUN handle instance.
 * @return `0` on success, or a negative error code on failure.
 */
int iptables_reset(tun_iface_t *tun);

/* ========================================================================= *
 * PARAMETER GETTER HELPERS                                                  *
 * ========================================================================= */

/**
 * @brief Gets the underlying system file descriptor for the TUN device node.
 *
 * @param[in]  tun    Pointer to the TUN handle instance.
 * @param[out] out_fd Output pointer to store the file descriptor.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_fd(const tun_iface_t* tun, int *out_fd);

/**
 * @brief Retrieves the current interface MTU setting.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] out_mtu Output pointer to store the MTU value.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_mtu(const tun_iface_t* tun, uint16_t *out_mtu);

/**
 * @brief Copies the interface network device name (e.g., "tun0") into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer.
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_ifname(const tun_iface_t* tun, char* buf, size_t buf_len);

/**
 * @brief Gets the interface IPv4 address as a binary struct.
 *
 * @param[in]  tun Pointer to the TUN handle instance.
 * @param[out] out Destination `in_addr` structure pointer.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_ip(const tun_iface_t* tun, struct in_addr* out);

/**
 * @brief Gets the primary DNS server IP address.
 *
 * @param[in]  tun Pointer to the TUN handle instance.
 * @param[out] out Destination `in_addr` structure pointer.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_dns1(const tun_iface_t* tun, struct in_addr* out);

/**
 * @brief Gets the secondary DNS server IP address.
 *
 * @param[in]  tun Pointer to the TUN handle instance.
 * @param[out] out Destination `in_addr` structure pointer.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_dns2(const tun_iface_t* tun, struct in_addr* out);

/**
 * @brief Gets the interface netmask as a binary struct.
 *
 * @param[in]  tun Pointer to the TUN handle instance.
 * @param[out] out Destination `in_addr` structure pointer.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_mask(const tun_iface_t* tun, struct in_addr* out);

/**
 * @brief Gets the calculated network address as a binary struct.
 *
 * @param[in]  tun Pointer to the TUN handle instance.
 * @param[out] out Destination `in_addr` structure pointer.
 * @return `0` on success, or `-EINVAL` if parameters are invalid.
 */
int tun_get_net(const tun_iface_t* tun, struct in_addr* out);

/**
 * @brief Copies the IPv4 address string into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer (recommended min size: `INET_ADDRSTRLEN`).
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_ip_str(const tun_iface_t* tun, char* buf, size_t buf_len);

/**
 * @brief Copies the netmask string into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer (recommended min size: `INET_ADDRSTRLEN`).
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_mask_str(const tun_iface_t* tun, char* buf, size_t buf_len);

/**
 * @brief Copies the calculated network address string into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer (recommended min size: `INET_ADDRSTRLEN`).
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_net_str(const tun_iface_t* tun, char* buf, size_t buf_len);

/**
 * @brief Copies the IP address with CIDR prefix notation (e.g., "10.0.0.1/24") into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer.
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_ip_cidr(const tun_iface_t* tun, char* buf, size_t buf_len);

/**
 * @brief Copies the Network address with CIDR prefix notation (e.g., "10.0.0.0/24") into a buffer.
 *
 * @param[in]  tun     Pointer to the TUN handle instance.
 * @param[out] buf     Destination string buffer.
 * @param[in]  buf_len Size of the destination buffer in bytes.
 * @return `0` on success, or a negative error code on failure.
 */
int tun_get_net_cidr(const tun_iface_t* tun, char* buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif // TUN_API_H