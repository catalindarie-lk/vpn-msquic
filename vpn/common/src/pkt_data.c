
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#include "log.h"
#include "pkt_data.h"


int pkt_data_iphdr(const uint8_t* pkt, ssize_t len, struct in_addr* src, struct in_addr* dest)
{
    // Guard against invalid pointers and length smaller than IPv4 header (20 bytes)
    if (!src || !dest) {
        return -EINVAL;
    }

    if (!pkt) {
        return -EINVAL;
    }

    if (len < (ssize_t)sizeof(struct iphdr)) {
        return -EINVAL;
    }

    const struct iphdr* ip = (const struct iphdr*)pkt;

    // Validate IP version (Must be IPv4)
    if (ip->version != 4) {
        return -ENOSPC;
    }

    // Extract addresses (ip->saddr and ip->daddr are already in Network Byte Order)
    src->s_addr  = ip->saddr;
    dest->s_addr = ip->daddr;

    return 0;
}

int pkt_data_print(uint64_t conn_id, bool inbound, uint8_t *buf, size_t len) {
    if (!buf || len < sizeof(struct iphdr)) {
        return -EINVAL;
    }

    const char *dir = inbound ? "<---" : "--->";
    uint8_t version = (buf[0] >> 4) & 0x0F;

    if (version == 4) {
        // Safe stack copy to avoid alignment traps
        struct iphdr iph;
        memcpy(&iph, buf, sizeof(struct iphdr));

        // Validate minimum IPv4 header length (minimum 5 words = 20 bytes)
        size_t ip_header_len = iph.ihl * 4;
        if (iph.ihl < 5 || len < ip_header_len) {
            LOG_DEBUG("[%s] cid:%" PRIu64 " %zub [IPv4 Malformed/Truncated Header]", dir, conn_id, len);
            return -EAFNOSUPPORT;
        }

        struct in_addr src_addr = { .s_addr = iph.saddr };
        struct in_addr dst_addr = { .s_addr = iph.daddr };

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        if (!inet_ntop(AF_INET, &src_addr, src_ip, sizeof(src_ip))) {
            return -EAFNOSUPPORT;
        }
        if (!inet_ntop(AF_INET, &dst_addr, dst_ip, sizeof(dst_ip))) {
            return -EAFNOSUPPORT;
        }

        switch (iph.protocol) {
            case IPPROTO_ICMP:
                LOG_TRACE("[%s] cid:%" PRIu64 " %zub [%s -> %s] : ICMP (Ping)",
                          dir, conn_id, len, src_ip, dst_ip);
                break;

            case IPPROTO_TCP: {
                if (len < (ip_header_len + sizeof(struct tcphdr))) {
                    LOG_DEBUG("[%s] cid:%" PRIu64 " %zub [%s -> %s] : TCP (Truncated)",
                              dir, conn_id, len, src_ip, dst_ip);
                    break;
                }
                struct tcphdr tcph;
                memcpy(&tcph, buf + ip_header_len, sizeof(struct tcphdr));

                LOG_TRACE("[%s] cid:%" PRIu64 " %zub [%s -> %s] [%u -> %u] : TCP",
                          dir, conn_id, len, src_ip, dst_ip, 
                          ntohs(tcph.source), ntohs(tcph.dest));
                break;
            }

            case IPPROTO_UDP: {
                if (len < (ip_header_len + sizeof(struct udphdr))) {
                    LOG_DEBUG("[%s] cid:%" PRIu64 " %zub [%s -> %s] : UDP (Truncated)",
                              dir, conn_id, len, src_ip, dst_ip);
                    break;
                }
                struct udphdr udph;
                memcpy(&udph, buf + ip_header_len, sizeof(struct udphdr));

                LOG_TRACE("[%s] cid:%" PRIu64 " %zub [%s -> %s] [%u -> %u] : UDP",
                          dir, conn_id, len, src_ip, dst_ip, 
                          ntohs(udph.source), ntohs(udph.dest));
                break;
            }

            default:
                LOG_DEBUG("[%s] cid:%" PRIu64 " %zub [%s -> %s] : Other (%u)",
                          dir, conn_id, len, src_ip, dst_ip, iph.protocol);
                break;
        }
    } else {
        LOG_DEBUG("[%s] cid:%" PRIu64 " %zub [Non-IPv4: v%u]", dir, conn_id, len, version);
    }
    return 0;
}