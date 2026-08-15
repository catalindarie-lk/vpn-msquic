

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "pkt_ctrl.h"
#include "utils.h"


pkt_ctrl_t* pkt_ctrl_create_config_req(uint64_t uid, uint8_t af_family, const char *hostname) 
{
    pkt_ctrl_t *pkt = calloc(1, sizeof(*pkt));
    if (!pkt) return NULL;

    pkt->hdr.frame_len  = htons((uint16_t)sizeof(*pkt));
    pkt->hdr.head_magic = htonl(HEAD_MAGIC);
    pkt->hdr.type       = htons(VPN_MSG_TYPE_CONFIG_REQ);
    pkt->hdr.uid        = htonll(uid);

    pkt->body.config_req.af_family = af_family;
    if (hostname) {
        snprintf(pkt->body.config_req.hostname, sizeof(pkt->body.config_req.hostname), "%s", hostname);
    }

    pkt->tail_magic = htonl(TAIL_MAGIC);
    return pkt;
}

pkt_ctrl_t* pkt_ctrl_create_config_resp(uint64_t uid,
                                       uint8_t status_code, uint16_t mtu,
                                       struct in_addr ip, struct in_addr mask,
                                       struct in_addr dns1, struct in_addr dns2) 
{
    pkt_ctrl_t *pkt = calloc(1, sizeof(*pkt));
    if (!pkt) return NULL;

    pkt->hdr.frame_len  = htons((uint16_t)sizeof(*pkt));
    pkt->hdr.head_magic = htonl(HEAD_MAGIC);
    pkt->hdr.type       = htons(VPN_MSG_TYPE_CONFIG_RESP);
    pkt->hdr.uid        = htonll(uid);

    pkt->body.config_resp.status_code = htonl(status_code);
    pkt->body.config_resp.mtu         = htons(mtu);
    pkt->body.config_resp.ip           = ip;   // struct in_addr is already network byte order
    pkt->body.config_resp.mask         = mask;
    pkt->body.config_resp.dns1         = dns1;
    pkt->body.config_resp.dns2         = dns2;

    pkt->tail_magic = htonl(TAIL_MAGIC);
    return pkt;
}


//DEBUG
void pkt_ctrl_print(const pkt_ctrl_t* pkt) {
    if (!pkt) {
        printf("[VPN pkt] (NULL)\n");
        return;
    }

    const pkt_ctrl_hdr_t* hdr = &pkt->hdr;

    printf("┌─────────────────────────────────────────────────────────────┐\n");
    printf("│                      VPN CONTROL PKT                        │\n");
    printf("├─────────────────────────────────────────────────────────────┤\n");
    printf("│ PKT Len : %-5" PRIu16 " | Head Magic : 0x%08" PRIX32 " %s   |\n", 
           hdr->frame_len, hdr->head_magic, 
           (hdr->head_magic == HEAD_MAGIC) ? " [OK]" : "[BAD]");
    printf("│ UID    : %-5" PRIu64 " \n", 
           hdr->uid);
    printf("│ Msg Type  : %-5" PRIu16 " | Tail Magic : 0x%08" PRIX32 " %s |\n", 
           hdr->type, pkt->tail_magic,
           (pkt->tail_magic == TAIL_MAGIC) ? " [OK]" : "[BAD]");
    printf("├─────────────────────────────────────────────────────────────┤\n");

    switch (hdr->type) {
        case VPN_MSG_TYPE_CONFIG_REQ: {
            const pkt_ctrl_config_req_t* req = &pkt->body.config_req;
            printf("│ Message   : CONFIG_REQ\n");
            printf("│   AF Family : %" PRIu8 " (%s)\n", req->af_family, 
                   (req->af_family == AF_INET) ? "IPv4" : 
                   (req->af_family == AF_INET6) ? "IPv6" : "Unknown");
            printf("│   Hostname  : %.*s\n", (int)sizeof(req->hostname), req->hostname);
            break;
        }

        case VPN_MSG_TYPE_CONFIG_RESP: {
            const pkt_ctrl_config_resp_t* resp = &pkt->body.config_resp;
            char ip_str[INET_ADDRSTRLEN], mask_str[INET_ADDRSTRLEN], 
                 dns1_str[INET_ADDRSTRLEN], dns2_str[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &resp->ip, ip_str, sizeof(ip_str));
            inet_ntop(AF_INET, &resp->mask, mask_str, sizeof(mask_str));
            inet_ntop(AF_INET, &resp->dns1, dns1_str, sizeof(dns1_str));
            inet_ntop(AF_INET, &resp->dns2, dns2_str, sizeof(dns2_str));

            printf("│ Payload   : CONFIG_RESP\n");
            printf("│   Status  : %" PRIu32 " (%s)\n", resp->status_code, 
                   (resp->status_code == 0) ? "SUCCESS" : "ERROR");
            printf("│   Assigned: %s / %s\n", ip_str, mask_str);
            printf("│   TUN MTU : %" PRIu16 "\n", resp->mtu);
            printf("│   DNS 1   : %s\n", dns1_str);
            printf("│   DNS 2   : %s\n", dns2_str);
            break;
        }

        case VPN_MSG_TYPE_ROUTE_UPDATE: {
            const pkt_ctrl_route_update_t* route = &pkt->body.route_update;
            printf("│ Payload   : ROUTE_UPDATE (Count: %" PRIu16 ")\n", route->route_count);
            
            uint16_t count = route->route_count > 8 ? 8 : route->route_count; // Bound protection
            for (uint16_t i = 0; i < count; i++) {
                char dest[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &route->routes[i].dest_network, dest, sizeof(dest));
                inet_ntop(AF_INET, &route->routes[i].mask, mask, sizeof(mask));
                printf("│   [%" PRIu16 "] Subnet: %s / %s\n", i + 1, dest, mask);
            }
            break;
        }

        case VPN_MSG_TYPE_KEEPALIVE: {
            const pkt_ctrl_keepalive_t* ka = &pkt->body.keepalive;
            printf("│ Payload   : KEEPALIVE\n");
            printf("│   Client TS : %" PRIu64 " ms\n", ka->client_timestamp_ms);
            printf("│   Server TS : %" PRIu64 " ms\n", ka->server_timestamp_ms);
            break;
        }

        case VPN_MSG_TYPE_STATUS: {
            const pkt_ctrl_status_t* st = &pkt->body.status;
            printf("│ Payload   : STATUS / TEARDOWN\n");
            printf("│   Code   : %" PRIu32 "\n", st->error_code);
            printf("│   Reason : %.*s\n", (int)sizeof(st->reason), st->reason);
            break;
        }

        default:
            printf("│ Payload   : UNKNOWN / UNHANDLED (Type %" PRIu16 ")\n", hdr->type);
            break;
    }

    printf("└─────────────────────────────────────────────────────────────┘\n");
}
