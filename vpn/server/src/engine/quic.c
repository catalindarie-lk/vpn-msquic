
#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "log.h"
#include "msquic.h"
#include "quic.h"
#include "queue.h"
#include "pkt_ctrl.h"
#include "pkt_data.h"
#include "session.h"
#include "ip_pool.h"
#include "client.h"
#include "stream.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

#define SERVER_ERROR_FULL (0x110)
#define SERVER_ERROR_AUTH (0x111)

//========================================================================================================================
//                                              STATIC HELPERS
//========================================================================================================================

static inline void copy_quic_buffers(const QUIC_BUFFER* quic_buf, uint32_t buf_cnt, uint64_t offset, uint8_t* dest, uint32_t to_copy) 
{
    uint32_t copied = 0;
    
    for (uint32_t i = 0; i < buf_cnt && copied < to_copy; i++) {
        if (offset >= quic_buf[i].Length) {
            offset -= quic_buf[i].Length;
            continue;
        }

        uint32_t chunk = quic_buf[i].Length - (uint32_t)offset;
        if (chunk > (to_copy - copied)) {
            chunk = to_copy - copied;
        }

        memcpy(dest + copied, quic_buf[i].Buffer + offset, chunk);
        copied += chunk;
        offset = 0; // Offset only applies to the first chunk
    }
}

static inline int process_ctrl_pkt(session_t* session, stream_t* stream, pkt_ctrl_t* pkt)
{
    pkt_ctrl_t req_pkt = {
        .hdr.frame_len = ntohs(pkt->hdr.frame_len),
        .hdr.head_magic = ntohl(pkt->hdr.head_magic),
        .hdr.type = ntohs(pkt->hdr.type),
        .hdr.uid = ntohll(pkt->hdr.uid),
        .tail_magic = ntohl(pkt->tail_magic)
    };

    if (req_pkt.hdr.frame_len != sizeof(pkt_ctrl_t) ||
        req_pkt.hdr.head_magic != HEAD_MAGIC ||
        req_pkt.tail_magic != TAIL_MAGIC) 
    {   
        fprintf(stderr, "ERROR: frame dropped, invalid fields\n");
        return -1;
    }

    switch (req_pkt.hdr.type) {

        case VPN_MSG_TYPE_CONFIG_REQ:
            req_pkt.body.config_req.af_family = pkt->body.config_req.af_family;
            strncpy(req_pkt.body.config_req.hostname, pkt->body.config_req.hostname, HOSTNAMSIZ);
            
            pkt_ctrl_print(&req_pkt);

            struct in_addr assigned_ip = {0};
            
            uint64_t assigned_uid = stream->client->uid;

            client_t *client = list_find_client_by_uid(session, assigned_uid);

            if (!client) {
                LOG_WARNING("Received packet from unknown client. Ignore");
                return -1;
            }
                    
            // client->ip_entry = ip_acquire(session->ip_pool, client);
            // if (!client->ip_entry) {

            //     LOG_WARNING("[list][%p] Rejecting connection with AppErrorCode: 0x%llX", 
            //                 stream->StreamHandle, SERVER_ERROR_FULL);

            //     // application defined error code
            //     // TODO - implement error code also in client for logging the reason
            //     SERVER_QUIC_CONTEXT* MsQuic = stream->client->session->MsQuic;
            //     if (stream->StreamHandle) {
            //         MsQuic->Api->StreamShutdown(
            //             stream->StreamHandle,
            //             QUIC_STREAM_SHUTDOWN_FLAG_ABORT,
            //             SERVER_ERROR_FULL);
            //     }
            //     LOG_WARNING("no ip available");
            //     //TODO -> implement rejection frame
            //     return -1;
            // }

            assigned_ip = client->ip_entry->ip;
            LOG_DEBUG("Client UID [%d] assigned tunneling IP [%s]", assigned_uid, client->ip_entry->ip_str);

            uint16_t mtu = 0;
            tun_get_mtu(session->tun, &mtu);
            struct in_addr mask = {0};
            tun_get_mask(session->tun, &mask);
            struct in_addr dns1 = {0};
            tun_get_dns1(session->tun, &dns1);
            struct in_addr dns2 = {0};
            tun_get_dns2(session->tun, &dns2);


            pkt_ctrl_t* pkt = 
                pkt_ctrl_create_config_resp(
                    assigned_uid, 
                    0, 
                    mtu, 
                    assigned_ip,
                    mask,
                    dns1,
                    dns2
                );

            stream_send(stream, (uint8_t*)pkt, sizeof(pkt_ctrl_t));
            break;
        
        default:
            LOG_ERROR("Unsuported control packet type");
            break;
        
    }
    return 0;

}


//========================================================================================================================
//                                              QUIC CALLBACKS
//========================================================================================================================

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC StreamHandle,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    stream_t* stream = (stream_t*)Context;
    assert(stream);
    client_t* client = stream->client;
    assert(client);
    session_t* session = stream->session;
    assert(session);
    SERVER_QUIC_CONTEXT* MsQuic = session->MsQuic;
    assert(MsQuic);

    switch (Event->Type) {

        // =====================================================================
        // EVENT: SEND COMPLETE
        // =====================================================================
        case QUIC_STREAM_EVENT_SEND_COMPLETE: {
            if (Event->SEND_COMPLETE.ClientContext != NULL) {
                QUIC_BUFFER* quic_buf = (QUIC_BUFFER* )Event->SEND_COMPLETE.ClientContext;
                
                free(quic_buf->Buffer);
                free(quic_buf);
            }
            return QUIC_STATUS_SUCCESS;
        }
        // =====================================================================
        // EVENT: RECEIVE
        // =====================================================================
        case QUIC_STREAM_EVENT_RECEIVE:{

            uint64_t total_bytes = Event->RECEIVE.TotalBufferLength;
            uint64_t bytes_consumed = 0;

            while (total_bytes - bytes_consumed >= sizeof(pkt_ctrl_t)) {
                
                pkt_ctrl_t pkt = {0};

                copy_quic_buffers(
                    Event->RECEIVE.Buffers, 
                    Event->RECEIVE.BufferCount, 
                    bytes_consumed, 
                    (uint8_t*)&pkt, 
                    sizeof(pkt_ctrl_t)
                );

                process_ctrl_pkt(session, stream, &pkt);
                
                // Advance offset by sizeof(pkt_ctrl_t) bytes
                bytes_consumed += sizeof(pkt_ctrl_t);
            }

            // Update MsQuic with how many bytes we consumed
            Event->RECEIVE.TotalBufferLength = bytes_consumed;

            // If unconsumed bytes remain (< sizeof(pkt_ctrl_t) bytes), instruct MsQuic to keep buffering
            // if (bytes_consumed < total_bytes) {
            //     return QUIC_STATUS_CONTINUE; 
            // }

            return QUIC_STATUS_SUCCESS;
        }
        // =====================================================================
        // EVENT: PEER SEND SHUTDOWN
        // =====================================================================
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
            LOG_DEBUG("[strm][%p] Peer Gracefull FIN", StreamHandle);
            
            MsQuic->Api->StreamShutdown(
                StreamHandle, 
                QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 
                0);
            return QUIC_STATUS_SUCCESS;
        }
        // =====================================================================
        // EVENT: PEER SEND ABORTED
        // =====================================================================
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
            LOG_DEBUG("[strm][%p] Peer aborted send (ErrorCode: 0x%llX)", 
              StreamHandle, Event->PEER_SEND_ABORTED.ErrorCode);
            
            MsQuic->Api->StreamShutdown(
                StreamHandle, 
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, 
                0);
                
            return QUIC_STATUS_SUCCESS;
        }
        // =====================================================================
        // EVENT: SHUTDOWN COMPLETE
        // =====================================================================
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {
            LOG_DEBUG("[strm][%p] All done", StreamHandle);
        
            MsQuic->Api->StreamClose(StreamHandle);
            stream->StreamHandle = NULL;

            // ---------
            // If control stream is closed by peer then drop connection
            // since each client has only one stream (control stream)
            // if the stream is closed then drop the connection
            // --------
            // Error code can be used to inform client
            // why connection was shutdown by the server
            // QUIC_UINT62 ErrorCode // Application defined error code

            if (stream->client != NULL && stream->client->ConnectionHandle != NULL) {
                MsQuic->Api->ConnectionShutdown(
                    stream->client->ConnectionHandle, 
                    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 
                    0);
            }
            
            free(stream);

            return QUIC_STATUS_SUCCESS;
        }
        default:
            break;
    }
    return QUIC_STATUS_SUCCESS;
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC ConnectionHandle,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    client_t* client = (client_t* )Context;
    assert(client);
    session_t* session = client->session;
    assert(session);
    SERVER_QUIC_CONTEXT* MsQuic = session->MsQuic;
    assert(MsQuic);

    switch (Event->Type) {

        // =====================================================================
        // EVENT: DATAGRAM RECEIVED
        // =====================================================================
        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {

            if (Event->DATAGRAM_RECEIVED.Buffer->Length == 0) {
                return QUIC_STATUS_SUCCESS;
            }

            pkt_data_t *pkt = (pkt_data_t* )pool_try_get(session->pool_pkt_data_recv);
            if (!pkt) {
                return QUIC_STATUS_SUCCESS;
            }

            memcpy(pkt->data, Event->DATAGRAM_RECEIVED.Buffer->Buffer, Event->DATAGRAM_RECEIVED.Buffer->Length);
            pkt->buf.Buffer = pkt->data;
            pkt->buf.Length = Event->DATAGRAM_RECEIVED.Buffer->Length;

            queue_try_push(session->queue_pkt_data_recv, pkt);

            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: DATAGRAM SEND STATE CHANGED
        // =====================================================================
        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {

            pkt_data_t* pkt = Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
            
            switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
                case QUIC_DATAGRAM_SEND_SENT:
                    if (pkt != NULL) {
                        pool_put(pkt);
                    }
                    return QUIC_STATUS_SUCCESS;

                case QUIC_DATAGRAM_SEND_LOST_SUSPECT:
                case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
                    // Telemetry / Metrics only
                    return QUIC_STATUS_SUCCESS;

                case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
                case QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
                    // Telemetry / Metrics only
                    return QUIC_STATUS_SUCCESS;

                case QUIC_DATAGRAM_SEND_CANCELED:
                    if (pkt != NULL) {
                        pool_put(pkt);
                    }
                    return QUIC_STATUS_SUCCESS;

                default:
                    break;
            }
            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: CONNECTED
        // =====================================================================
        case QUIC_CONNECTION_EVENT_CONNECTED: {

            BOOLEAN Authorized = true;//CheckAppAuth(Event->NEW_CONNECTION.Info);

            if (!Authorized) {
                // Define application-specific error code
                // (e.g., SERVER_ERROR_AUTH = Unauthorized / Access Denied)
                QUIC_UINT62 AppErrorCode = SERVER_ERROR_AUTH;

                LOG_WARNING("[list][%p] Rejecting connection with AppErrorCode: 0x%llX", 
                        ConnectionHandle, SERVER_ERROR_AUTH);

                // Shut down the incoming connection handle explicitly with your error code
                MsQuic->Api->ConnectionShutdown(
                    ConnectionHandle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    SERVER_ERROR_AUTH
                );
                return QUIC_STATUS_CONNECTION_REFUSED;
            }

            if (initialize_client_state(client) != 0) {

                // ip_release(session->ip_pool, client->ip_entry);
                // list_remove_client(session, client);

                QUIC_UINT62 AppErrorCode = SERVER_ERROR_FULL;

                LOG_WARNING("[list][%p] Rejecting connection with AppErrorCode: 0x%llX", 
                        ConnectionHandle, SERVER_ERROR_FULL);

                // Shut down the incoming connection handle explicitly with your error code
                MsQuic->Api->ConnectionShutdown(
                    ConnectionHandle,
                    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    SERVER_ERROR_FULL
                );
                return QUIC_STATUS_CONNECTION_REFUSED;

            }

            LOG_DEBUG("New client connected. Assigned new UID: %" PRId64, client->uid);
        
            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: SHUTDOWN INITIATED BY TRANSPORT
        // =====================================================================
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: {
            if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
                LOG_DEBUG("[conn][%p] Successfully shut down on idle", ConnectionHandle);
            } else {
                LOG_DEBUG("[conn][%p] Shut down by transport, 0x%x", 
                    ConnectionHandle, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
            }
            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: SHUTDOWN INITIATED BY PEER
        // =====================================================================
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
            LOG_DEBUG("[conn][%p] Shut down by peer, 0x%lu", 
                ConnectionHandle, (uint64_t)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: SHUTDOWN COMPLETE
        // =====================================================================
        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            LOG_DEBUG("QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE [conn][%p]", 
                ConnectionHandle);
            
            ip_release(session->ip_pool, client->ip_entry);
            list_remove_client(session, client);
            
            client->ConnectionHandle = NULL;

            if (ConnectionHandle) {
                MsQuic->Api->ConnectionClose(client->ConnectionHandle);
            }
            
            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: PEER STREAM STARTED
        // =====================================================================
        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {

            stream_t* stream = malloc(sizeof(stream_t));
            if (!stream) {
                MsQuic->Api->StreamClose(Event->PEER_STREAM_STARTED.Stream);
                return QUIC_STATUS_OUT_OF_MEMORY;
            }
            memset(stream, 0, sizeof(stream_t));

            stream->StreamHandle = Event->PEER_STREAM_STARTED.Stream;
            stream->session = session;
            stream->client = client;

            MsQuic->Api->SetCallbackHandler(
                Event->PEER_STREAM_STARTED.Stream, 
                (void*)ServerStreamCallback, 
                stream);

            return QUIC_STATUS_SUCCESS;
        }

        // =====================================================================
        // EVENT: RESUMED
        // =====================================================================
        case QUIC_CONNECTION_EVENT_RESUMED: {
            LOG_DEBUG("[conn][%p] Connection resumed!", client->ConnectionHandle);
            return QUIC_STATUS_SUCCESS;
        }

        default:
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC ListenerHandle,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(ListenerHandle);

    session_t* session = (session_t*)Context;
    assert(session);
    SERVER_QUIC_CONTEXT* MsQuic = session->MsQuic;
    assert(MsQuic);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    switch (Event->Type) {

        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            HQUIC NewConnection = Event->NEW_CONNECTION.Connection;

            client_t* client = list_add_client(session, NewConnection);
            if (!client) {
                // Returning failure tells MsQuic to reject and clean up the connection handle
                return QUIC_STATUS_OUT_OF_MEMORY;
            }

            // Set the connection callback handler
            MsQuic->Api->SetCallbackHandler(
                NewConnection,
                (void*)ServerConnectionCallback,
                client);

            // Bind server configuration (TLS / ALPN / Certificate)
            Status = MsQuic->Api->ConnectionSetConfiguration(
                NewConnection,
                MsQuic->Configuration);

            if (QUIC_FAILED(Status)) {
                LOG_ERROR("ConnectionSetConfiguration() failed: 0x%x", Status);

                list_remove_client(session, client);

                // Explicitly close the connection handle on configuration error
                MsQuic->Api->ConnectionClose(NewConnection);

                return Status;
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_LISTENER_EVENT_STOP_COMPLETE: {
            LOG_DEBUG("MsQuic Listener stop completed");
            return QUIC_STATUS_SUCCESS;
        }

        default:
            LOG_WARNING("Unhandled Listener event type: %u", Event->Type);
            break;
    }

    return QUIC_STATUS_SUCCESS;
}

//========================================================================================================================
//                                                  QUIC
//========================================================================================================================

SERVER_QUIC_CONTEXT *MsQuicCreate() {
        
    SERVER_QUIC_CONTEXT *MsQuic = (SERVER_QUIC_CONTEXT*)calloc(1, sizeof(SERVER_QUIC_CONTEXT));
    if (!MsQuic) {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    return MsQuic;
}

int MsQuicRegister(SERVER_QUIC_CONTEXT *MsQuic, const char *app_name, int exec_profile)
{

    if (!MsQuic || !app_name) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuicOpen2(&MsQuic->Api);

    if QUIC_FAILED(Status) {
        LOG_ERROR("MsQuicOpen2() failed, Status: 0x%x!", Status);
        return -ECANCELED;
    }

    MsQuic->RegConfig.AppName = app_name;
    MsQuic->RegConfig.ExecutionProfile = (QUIC_EXECUTION_PROFILE)exec_profile;

    Status = MsQuic->Api->RegistrationOpen(
        &MsQuic->RegConfig, 
        &MsQuic->Registration
    );
    
    if QUIC_FAILED(Status) {
        LOG_ERROR("RegistrationOpen() failed, Status: 0x%x!", Status);
        return -ECANCELED;
    }

    return 0;

}

int MsQuicConfigLocalAddr(SERVER_QUIC_CONTEXT *MsQuic, const char* local_addr, uint16_t port) {
    
    if (!MsQuic || !local_addr) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    memset(&MsQuic->LocalAddr, 0, sizeof(MsQuic->LocalAddr));

    if (!QuicAddrFromString(
                local_addr, 
                port, 
                &MsQuic->LocalAddr))
    {
        LOG_ERROR("Network: The provided bind ip is invalid: [%s]", local_addr);
        return -EINVAL;
    }

    int si_family = QuicAddrGetFamily(&MsQuic->LocalAddr);

    if (si_family != AF_INET) {
        LOG_ERROR("Network: The provided bind ip family is not supported: [%d]", si_family);
        return -EINVAL;
    }
    QuicAddrSetPort(&MsQuic->LocalAddr, port);
    return 0;

}


int MsQuicConfigCredentials(SERVER_QUIC_CONTEXT *MsQuic, const char* cert_file, const char* key_file, const char* private_key_password) {
    
    if (!MsQuic) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    memset(&MsQuic->Creds, 0, sizeof(QUIC_CREDENTIAL_CONFIG_HELPER));
    MsQuic->Creds.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    if (cert_file != NULL && key_file != NULL) {
        
        if (private_key_password != NULL) {
            LOG_DEBUG("QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED");
            MsQuic->Creds.CertFileProtected.CertificateFile = (char*)cert_file;
            MsQuic->Creds.CertFileProtected.PrivateKeyFile = (char*)key_file;
            MsQuic->Creds.CertFileProtected.PrivateKeyPassword = (char*)private_key_password;
            MsQuic->Creds.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            MsQuic->Creds.CredConfig.CertificateFileProtected = &MsQuic->Creds.CertFileProtected;
            LOG_DEBUG("cert_file: %s, key_file: %s, password: %s", cert_file, key_file, private_key_password);
        } else {
            LOG_DEBUG("QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE");
            MsQuic->Creds.CertFile.CertificateFile = (char*)cert_file;
            MsQuic->Creds.CertFile.PrivateKeyFile = (char*)key_file;
            MsQuic->Creds.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            MsQuic->Creds.CredConfig.CertificateFile = &MsQuic->Creds.CertFile;
        }
    } else {
        LOG_DEBUG("Security credential configuration error");
        return -EINVAL;
    }

    return 0;
}

int MsQuicConfigParameters(SERVER_QUIC_CONTEXT *MsQuic, const char* alpn)
{

    if (!MsQuic || !alpn) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    MsQuic->Alpn.Length = (uint32_t)strlen(alpn);
    MsQuic->Alpn.Buffer = (uint8_t*)alpn;

    // Clear and initialize the settings structure
    memset(&MsQuic->Settings, 0, sizeof(MsQuic->Settings));

    // Set the Disconnect Timeout to 2 min
    MsQuic->Settings.DisconnectTimeoutMs = 2 * 60 * 1000;//2 * 60 * 1000;
    MsQuic->Settings.IsSet.DisconnectTimeoutMs = TRUE;

    // Set the handshake timeouts to 30 sec
    MsQuic->Settings.HandshakeIdleTimeoutMs = 30 * 1000;
    MsQuic->Settings.IsSet.HandshakeIdleTimeoutMs = TRUE;

    // Set the Idle Timeout to infinite
    MsQuic->Settings.IdleTimeoutMs = 0;
    MsQuic->Settings.IsSet.IdleTimeoutMs = TRUE;

    // Send background heartbeats every 15 sec
    MsQuic->Settings.KeepAliveIntervalMs = 10 * 1000;
    MsQuic->Settings.IsSet.KeepAliveIntervalMs = TRUE;

    // Ensure Connection Migration is explicitly turned ON
    MsQuic->Settings.MigrationEnabled = TRUE;
    MsQuic->Settings.IsSet.MigrationEnabled = TRUE;

    bool unreliable = true;

    if (unreliable) {
        MsQuic->Settings.DatagramReceiveEnabled = 1;
        MsQuic->Settings.IsSet.DatagramReceiveEnabled = 1;

        // Set Max MTU to align with physical eth0 limits (1500 bytes)        
        MsQuic->Settings.MaximumMtu = 1480;
        MsQuic->Settings.IsSet.MaximumMtu = 1;
        // IPv6 baseline minimum
        MsQuic->Settings.MinimumMtu = 1280; 
        MsQuic->Settings.IsSet.MinimumMtu = 1;
    }

    // Configure resumption
    MsQuic->Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    MsQuic->Settings.IsSet.ServerResumptionLevel = TRUE;
    MsQuic->Settings.PeerBidiStreamCount = PEERBIDISTREAMCOUNT;
    MsQuic->Settings.IsSet.PeerBidiStreamCount = TRUE;
    
    return 0;

}

int MsQuicListenerStart(SERVER_QUIC_CONTEXT *MsQuic, void* ListenerContext) {

    if (!MsQuic) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuic->Api->ConfigurationOpen(
        MsQuic->Registration, 
        &MsQuic->Alpn, 
        1, 
        &MsQuic->Settings, 
        sizeof(MsQuic->Settings), 
        NULL, 
        &MsQuic->Configuration
    );

    if QUIC_FAILED(Status) {
        LOG_ERROR("MsQuic Api ConfigurationOpen() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }

    Status = MsQuic->Api->ConfigurationLoadCredential(
        MsQuic->Configuration, 
        &MsQuic->Creds.CredConfig
    );

    if QUIC_FAILED(Status) {
        LOG_ERROR("MsQuic Api ConfigurationLoadCredential() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }

    MsQuic->Listener = NULL;

    Status = MsQuic->Api->ListenerOpen(
        MsQuic->Registration, 
        ServerListenerCallback, 
        ListenerContext, 
        &MsQuic->Listener
    );

    if QUIC_FAILED(Status) {
        LOG_ERROR("MsQuic Api ListenerOpen() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }

    Status = MsQuic->Api->ListenerStart(
        MsQuic->Listener, 
        &MsQuic->Alpn, 
        1, 
        &MsQuic->LocalAddr
    );

    if QUIC_FAILED(Status) {
        LOG_ERROR("MsQuic Api ListenerStart() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }

    return 0;
}

int MsQuicShutdown(SERVER_QUIC_CONTEXT *MsQuic) {
    if (!MsQuic) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    MsQuic->Api->RegistrationShutdown(
        MsQuic->Registration,
        QUIC_CONNECTION_SHUTDOWN_FLAG_SILENT, // Force silent abort (no wire drain)
        0                                       // Error code
    );
   
    if (MsQuic->Api != NULL) {
        if (MsQuic->Listener != NULL) {
            MsQuic->Api->ListenerClose(MsQuic->Listener);
        }
        if (MsQuic->Configuration != NULL) {
            MsQuic->Api->ConfigurationClose(MsQuic->Configuration);
        }
        if (MsQuic->Registration != NULL) {
            MsQuic->Api->RegistrationClose(MsQuic->Registration);
        }
        MsQuicClose(MsQuic->Api);
    }
    free(MsQuic);
    return 0;
}

