#ifndef PHT_CTRL_H
#define PHT_CTRL_H

#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HEAD_MAGIC (0xAABBCCDD)
#define TAIL_MAGIC (0XDDBBCCAA)

#define PKTCTRLSIZ (1024)
#define HOSTNAMSIZ (64)

typedef struct stream_t stream_t;

typedef enum : uint16_t{
    VPN_MSG_TYPE_UNKNOWN        = 0,
    VPN_MSG_TYPE_CONFIG_REQ     = 1,
    VPN_MSG_TYPE_CONFIG_RESP    = 2,
    VPN_MSG_TYPE_ROUTE_UPDATE   = 3,
    VPN_MSG_TYPE_KEEPALIVE      = 4,
    VPN_MSG_TYPE_STATUS         = 5
} pkt_ctrl_type_t;

/* =========================================================================
 * 1. INDIVIDUAL MESSAGE STRUCTURES
 * ========================================================================= */

// Message 1: Client Requesting IP/TUN Config
typedef struct __attribute__((packed)) {
    uint8_t  af_family;        // AF_INET (IPv4) or AF_INET6 (IPv6)
    char     hostname[HOSTNAMSIZ];     // Null-terminated string
} pkt_ctrl_config_req_t;

// Message 2: Server Responding with Virtual IP Config
typedef struct __attribute__((packed)) {
    uint64_t uid;
    uint32_t status_code;      // 0 = Success, >0 = Error
    struct in_addr ip;  // Virtual IPv4 assigned for tun device
    struct in_addr mask;    // Netmask (e.g., 255.255.255.0)
    struct in_addr dns1;
    struct in_addr dns2;
    uint16_t mtu;     // Recommended TUN MTU
} pkt_ctrl_config_resp_t;

// Sub-structure for Route Update
typedef struct __attribute__((packed)) {
    struct in_addr dest_network;
    struct in_addr mask;
} route_entry_t;

// Message 3: Route Update Push (Server -> Client)
typedef struct __attribute__((packed)) {
    uint16_t          route_count;
    route_entry_t routes[8]; // Up to 8 subnets pushed dynamically
} pkt_ctrl_route_update_t;

// Message 4: Keepalive / Heartbeat
typedef struct __attribute__((packed)) {
    uint64_t client_timestamp_ms;
    uint64_t server_timestamp_ms;
} pkt_ctrl_keepalive_t;

// Message 5: Status, Errors, and Teardown
typedef struct __attribute__((packed)) {
    uint32_t error_code;
    char     reason[128];
} pkt_ctrl_status_t;


/* =========================================================================
 * 2. MASTER MESSAGE UNION (Container for all message payloads)
 * ========================================================================= */

typedef union {
    pkt_ctrl_config_req_t   config_req;
    pkt_ctrl_config_resp_t  config_resp;
    pkt_ctrl_route_update_t route_update;
    pkt_ctrl_keepalive_t    keepalive;
    pkt_ctrl_status_t       status;
} pkt_ctrl_type_u;

/* =========================================================================
 * 3. MASTER FRAME STRUCTURE (Header + Union/Padding + Tail Magic)
 * ========================================================================= */

typedef struct __attribute__((packed)) pkt_ctrl_hdr_t {
    uint16_t frame_len;   // Total bytes in frame (always 1024 for fixed frame)
    uint32_t head_magic;  // HEAD_MAGIC (0x56504E31)
    uint16_t type;    // Message Type Identifier
    uint64_t uid;
} pkt_ctrl_hdr_t;           // 16 Bytes

// Header (16B) + Union/Padding (1004B) + Tail Magic (4B) = 1024 Bytes
typedef struct __attribute__((packed)) {
    pkt_ctrl_hdr_t hdr;
    
    union {
        pkt_ctrl_type_u  body; // Access any message payload directly
        uint8_t          raw_padding[PKTCTRLSIZ - sizeof(pkt_ctrl_hdr_t) - sizeof(uint32_t)];
    };

    uint32_t tail_magic; // Placed at the absolute end of the frame (bytes 1020..1023)
} pkt_ctrl_t;


void pkt_ctrl_print(const pkt_ctrl_t* pkt);

//SERVER
pkt_ctrl_t* pkt_ctrl_create_config_req(uint64_t uid, uint8_t af_family, const char *hostname);

//CLIENT
pkt_ctrl_t* pkt_ctrl_create_config_resp(uint64_t uid,
                                       uint8_t status_code, uint16_t mtu,
                                       struct in_addr ip, struct in_addr mask,
                                       struct in_addr dns1, struct in_addr dns2) ;

                                       

#ifdef __cplusplus
}
#endif

#endif // CONTROL_FRAME_H