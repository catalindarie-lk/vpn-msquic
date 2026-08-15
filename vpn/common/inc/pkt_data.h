#ifndef PKT_DATA_H
#define PKT_DATA_H

#include "msquic.h"

#include <stdint.h>
#include <stdbool.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define DATAPKTBUF 2048

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pkt_data_t {
    QUIC_BUFFER buf;
    uint8_t data[DATAPKTBUF];
} pkt_data_t;

int pkt_data_iphdr(const uint8_t* pkt, ssize_t len, struct in_addr* src, struct in_addr* dest);

int pkt_data_print(uint64_t conn_id, bool inbound, uint8_t *buf, size_t len);


#ifdef __cplusplus
}
#endif

#endif