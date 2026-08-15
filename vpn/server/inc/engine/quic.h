#ifndef QUIC_H
#define QUIC_H

// #include "cli.h"
#include <msquic.h>

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define _CRT_SECURE_NO_WARNINGS 1
#define QUIC_API_ENABLE_PREVIEW_FEATURES 1

#ifndef PEERBIDISTREAMCOUNT
#define PEERBIDISTREAMCOUNT (4)
#endif

typedef struct stream_t stream_t;
typedef struct client_t client_t;
typedef struct session_t session_t;

typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
    QUIC_CREDENTIAL_CONFIG CredConfig;
    union {
        QUIC_CERTIFICATE_HASH CertHash;
        QUIC_CERTIFICATE_HASH_STORE CertHashStore;
        QUIC_CERTIFICATE_FILE CertFile;
        QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
    };
} QUIC_CREDENTIAL_CONFIG_HELPER;

typedef struct SERVER_QUIC_CONTEXT {
        const QUIC_API_TABLE *Api;
        HQUIC Registration;
        HQUIC Configuration;
        HQUIC Listener;
        QUIC_REGISTRATION_CONFIG RegConfig;
        QUIC_SETTINGS Settings;
        QUIC_CREDENTIAL_CONFIG_HELPER Creds;
        QUIC_BUFFER Alpn;
        QUIC_ADDR LocalAddr;
} SERVER_QUIC_CONTEXT;


//========================================================================================================================
//                                              QUIC CALLBACKS
//========================================================================================================================

QUIC_STATUS ServerStreamCallback(HQUIC StreamHandle, void* Context, QUIC_STREAM_EVENT* Event);

QUIC_STATUS ServerConnectionCallback(HQUIC ConnectionHandle, void* Context, QUIC_CONNECTION_EVENT* Event);

QUIC_STATUS ServerListenerCallback(HQUIC ListenerHandle, void* Context, QUIC_LISTENER_EVENT* Event);


//========================================================================================================================
//                                                  QUIC
//========================================================================================================================

SERVER_QUIC_CONTEXT *MsQuicCreate();

int MsQuicRegister(SERVER_QUIC_CONTEXT *MsQuic, const char *app_name, int exec_profile);

int MsQuicConfigLocalAddr(SERVER_QUIC_CONTEXT *MsQuic, const char* local_ip, uint16_t port);

int MsQuicConfigCredentials(SERVER_QUIC_CONTEXT *MsQuic, const char* cert_file, const char* key_file, const char* private_key_password);

int MsQuicConfigParameters(SERVER_QUIC_CONTEXT *MsQuic, const char* alpn);

int MsQuicListenerStart(SERVER_QUIC_CONTEXT *MsQuic, void* ListenerContext);

int MsQuicShutdown(SERVER_QUIC_CONTEXT *MsQuic);


#endif