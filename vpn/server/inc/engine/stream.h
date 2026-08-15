#ifndef STREAM_H
#define STREAM_H

#include "ip_pool.h"
#include "msquic.h"
#include "quic.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct session_t session_t;
typedef struct client_t client_t;

typedef struct stream_t {
    HQUIC StreamHandle;
    SERVER_QUIC_CONTEXT *MsQuic;
    session_t* session;
    client_t* client;
} stream_t;

stream_t* stream_create();

int stream_send(stream_t *stream, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif