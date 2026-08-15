#ifndef QUIC_H
#define QUIC_H

#include <stdint.h>
#include <stdbool.h>

#include "msquic.h"
#include "session.h"


typedef struct CLIENT_QUIC_CONTEXT {
    const QUIC_API_TABLE* Api;
    HQUIC ConnectionHandle;
    HQUIC StreamHandle;
    HQUIC Registration;
    HQUIC Configuration;
    QUIC_SETTINGS Settings;
    QUIC_REGISTRATION_CONFIG RegConfig;
    QUIC_CREDENTIAL_CONFIG CredConfig;
    QUIC_BUFFER Alpn;
    uint8_t* ResumptionTicketBuffer;
    uint32_t ResumptionTicketLength;
    QUIC_ADDR LocalAddr;
    QUIC_ADDR ServerAddr;
} CLIENT_QUIC_CONTEXT;


QUIC_STATUS msquic_stream_callback(HQUIC StreamHandle, void* Context, QUIC_STREAM_EVENT* Event);

QUIC_STATUS msquic_connect_callback(HQUIC ConnectionHandle, void* Context, QUIC_CONNECTION_EVENT* Event);

CLIENT_QUIC_CONTEXT *MsQuicCreate();
int MsQuicRegister(CLIENT_QUIC_CONTEXT *MsQuic, const char *app_name, int exec_profile);
int MsQuicConfigAddr(CLIENT_QUIC_CONTEXT *MsQuic, const char* local_addr, const char* server_addr, uint16_t server_port);
int MsQuicConfigParameters(CLIENT_QUIC_CONTEXT *MsQuic, const char* alpn);
int MsQuicConfigCredentials(CLIENT_QUIC_CONTEXT *MsQuic);

int MsQuicConnectionStart(CLIENT_QUIC_CONTEXT *MsQuic, session_t *session);

int MsQuicStreamStart(CLIENT_QUIC_CONTEXT *MsQuic, session_t *session);
int MsQuicStreamSend(CLIENT_QUIC_CONTEXT* MsQuic, uint8_t *buf, size_t len);

int MsQuicShutdown(CLIENT_QUIC_CONTEXT *MsQuic);
#endif