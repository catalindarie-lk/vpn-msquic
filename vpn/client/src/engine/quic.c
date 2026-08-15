/* 1. Standard C Library Headers */
#include <stdbool.h>
#include <string.h>

/* 2. System, POSIX, and Linux Kernel Headers */
#include <arpa/inet.h>
#include <asm-generic/errno-base.h>
#include <asm-generic/errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* 3. Third-Party Library Headers */
#include "msquic.h"
#include "tun_driver.h"

/* 4. Internal Project Headers */
#include "log.h"
#include "pkt_ctrl.h"
#include "pkt_data.h"
#include "quic.h"
#include "session.h"
#include "state_sync.h"
#include "tun_api.h"
#include "utils.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

static inline int process_ctrl_pkt(session_t* session, pkt_ctrl_t *pkt_raw)
{
    pkt_ctrl_t pkt = {0};

    pkt.hdr.frame_len = ntohs(pkt_raw->hdr.frame_len);
    pkt.hdr.head_magic = ntohl(pkt_raw->hdr.head_magic);
    pkt.hdr.type = ntohs(pkt_raw->hdr.type);
    pkt.hdr.uid = ntohll(pkt_raw->hdr.uid);

    pkt.tail_magic = ntohl(pkt_raw->tail_magic);

    if (pkt.hdr.frame_len != sizeof(pkt_ctrl_t) ||
        pkt.hdr.head_magic != HEAD_MAGIC ||
        pkt.tail_magic != TAIL_MAGIC) 
    {   
        LOG_ERROR("Packet dropped, invalid fields");
        return 0;
    }

    switch (pkt.hdr.type) {

        case VPN_MSG_TYPE_CONFIG_RESP:

            pkt.body.config_resp.ip = pkt_raw->body.config_resp.ip;
            pkt.body.config_resp.mask = pkt_raw->body.config_resp.mask;
            pkt.body.config_resp.dns1 = pkt_raw->body.config_resp.dns1;
            pkt.body.config_resp.dns2 = pkt_raw->body.config_resp.dns2;
            pkt.body.config_resp.mtu = ntohs(pkt_raw->body.config_resp.mtu);
            pkt_ctrl_print(&pkt);

            struct in_addr ip = pkt_raw->body.config_resp.ip;
            struct in_addr mask = pkt_raw->body.config_resp.mask;
            struct in_addr dns1 = pkt_raw->body.config_resp.dns1;
            struct in_addr dns2 = pkt_raw->body.config_resp.dns2;
            struct in_addr net = {0};
            net.s_addr = ip.s_addr & mask.s_addr;
            uint16_t mtu = ntohs(pkt_raw->body.config_resp.mtu);

            char ip_str[INET_ADDRSTRLEN] = {0};
            char mask_str[INET_ADDRSTRLEN] = {0};
            char dns1_str[INET_ADDRSTRLEN] = {0};
            char dns2_str[INET_ADDRSTRLEN] = {0};
            char net_str[INET_ADDRSTRLEN] = {0};
            char net_cidr[INET_CIDRSTRLEN] = {0};

            in_addr_to_str(&ip, ip_str, INET_ADDRSTRLEN);
            in_addr_to_str(&mask, mask_str, INET_ADDRSTRLEN);
            in_addr_to_str(&dns1, dns1_str, INET_ADDRSTRLEN);
            in_addr_to_str(&dns2, dns2_str, INET_ADDRSTRLEN);
            in_addr_to_str(&net, net_str, INET_ADDRSTRLEN);
            in_addr_to_cidr(&net, &mask, net_cidr, INET_CIDRSTRLEN);

            tun_iface_t* tun = tun_create(TUN_BACKEND_NETLINK_CLIENT);
            if (!tun) goto cleanup;
            
            if (tun_open(tun) != 0) goto cleanup;
            if (tun_set_addr(tun, ip_str, mask_str) != 0) goto cleanup;
            if (tun_set_mtu(tun, mtu) != 0) goto cleanup;
            if (tun_set_up(tun) != 0) goto cleanup;

            if (tun_set_dns(tun, dns1_str, dns2_str) != 0) goto cleanup;

            if (tun_add_route(tun, "0.0.0.0/1") != 0) goto cleanup;
            if (tun_add_route(tun, "128.0.0.0/1") != 0) goto cleanup;
            if (tun_add_route(tun, net_cidr) != 0) goto cleanup;

            // if (tun_client_nat_rules_add(tun, 
            //     session->wan->ifname, 
            //     session->server_ip, 
            //     session->server_port) != 0) goto cleanup; 

            if (tun_start(tun) != 0) goto cleanup;

            session->tun = tun;
            state_sync_set(&session->tun_state, TUN_READY);
            return 0;

        cleanup:

            tun_flush_routes(tun);
            tun_clear_dns(tun);
            tun_set_down(tun);
            tun_destroy(tun);
            state_sync_set(&session->tun_state, TUN_FAIL);
            return -ENODEV;
        
        default:
            break;
        
    }
    return 0;

}

static inline void copy_quic_buffers(const QUIC_BUFFER* Buffers, uint32_t BufferCount, uint64_t Offset, uint8_t* Destination, uint32_t BytesToCopy)
{
    uint32_t copied = 0;
    
    for (uint32_t i = 0; i < BufferCount && copied < BytesToCopy; i++) {
        if (Offset >= Buffers[i].Length) {
            Offset -= Buffers[i].Length;
            continue;
        }

        uint32_t chunk = Buffers[i].Length - (uint32_t)Offset;
        if (chunk > (BytesToCopy - copied)) {
            chunk = BytesToCopy - copied;
        }

        memcpy(Destination + copied, Buffers[i].Buffer + Offset, chunk);
        copied += chunk;
        Offset = 0; // Offset only applies to the first chunk
    }
}


_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
msquic_stream_callback(
    _In_ HQUIC StreamHandle,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    session_t *session = (session_t*)Context;
    assert(session);
    CLIENT_QUIC_CONTEXT *MsQuic = session->MsQuic;
    assert(MsQuic);
    
    switch (Event->Type) {
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_START_COMPLETE
        // ============================================================================
        case QUIC_STREAM_EVENT_START_COMPLETE: {
            
            bool success = Event->START_COMPLETE.PeerAccepted && 
                            QUIC_SUCCEEDED(Event->START_COMPLETE.Status);
            if (!success) {
                state_sync_set(&session->stream_state, STREAM_CLOSED);                   
                LOG_ERROR("Control channel open failed (Status: 0x%x, PeerAccepted: %d)", 
                            Event->START_COMPLETE.Status, 
                            Event->START_COMPLETE.PeerAccepted);
            } else {
                state_sync_set(&session->stream_state, STREAM_OPEN);
                LOG_DEBUG("Control channel sucessfully open");
            }
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_RECEIVE
        // ============================================================================
        case QUIC_STREAM_EVENT_RECEIVE: {

            uint64_t recv_bytes = Event->RECEIVE.TotalBufferLength;
            if (recv_bytes == 0) return QUIC_STATUS_PROTOCOL_ERROR;

            uint64_t consumed_bytes = 0;

            // Loop to process all full frames currently in the stream buffer
            while (recv_bytes - consumed_bytes >= sizeof(pkt_ctrl_t)) {
                
                // Stack allocation for copying linear frame bytes out of MsQuic buffers
                pkt_ctrl_t pkt_raw = {0};
                // Copy sizeof(vpn_frame_t) contiguous bytes from MsQuic buffer array
                copy_quic_buffers(
                    Event->RECEIVE.Buffers, 
                    Event->RECEIVE.BufferCount, 
                    consumed_bytes, 
                    (uint8_t*)&pkt_raw, 
                    sizeof(pkt_ctrl_t)
                );

                if (process_ctrl_pkt(session, &pkt_raw) != 0) {
                    return QUIC_STATUS_ABORTED;
                }
                // Advance offset
                consumed_bytes += sizeof(pkt_ctrl_t);
            }

            // Update MsQuic with how many bytes consumed
            Event->RECEIVE.TotalBufferLength = consumed_bytes;
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_SEND_COMPLETE
        // ============================================================================
        case QUIC_STREAM_EVENT_SEND_COMPLETE: {
        
            QUIC_BUFFER* quic_buffer = (QUIC_BUFFER* )Event->SEND_COMPLETE.ClientContext;

            if (!quic_buffer) {
                LOG_ERROR("QUIC_STREAM_EVENT_SEND_COMPLETE -> invalid buffer pointer");
                return QUIC_STATUS_PROTOCOL_ERROR;
            }

            free(quic_buffer->Buffer);
            free(quic_buffer);

            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
        // ============================================================================
        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
            // Peer finished sending (end of response)
            LOG_WARNING("QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN");
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_PEER_SEND_ABORTED
        // ============================================================================
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
            LOG_WARNING("QUIC_STREAM_EVENT_PEER_SEND_ABORTED: code=%llu", 
                (unsigned long long)Event->PEER_SEND_ABORTED.ErrorCode);
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED
        // ============================================================================
        case QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED: {
            LOG_WARNING("QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED: code=%llu", 
                (unsigned long long)Event->PEER_RECEIVE_ABORTED.ErrorCode);
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
        // ============================================================================
        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE: {

            if (!Event->SEND_SHUTDOWN_COMPLETE.Graceful) {
                // Outbound delivery failed or was aborted before completion.
                LOG_WARNING("QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE -> not graceful");
            } else {
                // Outbound fully flushed and wire ack-ed by the peer. This is the normal path for stream completion.
                LOG_DEBUG("QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE -> graceful");
            }
             
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
        // ============================================================================
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {

            state_sync_set(&session->stream_state, STREAM_CLOSED);

            MsQuic->StreamHandle = NULL;

            if(StreamHandle) {
                MsQuic->Api->StreamClose(StreamHandle);
            }

            if(MsQuic->ConnectionHandle) {
                MsQuic->Api->ConnectionShutdown(
                    MsQuic->ConnectionHandle, 
                    QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 
                    0
                );
            }
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE
        // ============================================================================
        case QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE:{
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_PEER_ACCEPTED
        // ============================================================================
        case QUIC_STREAM_EVENT_PEER_ACCEPTED:{
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: QUIC_STREAM_EVENT_CANCEL_ON_LOSS
        // ============================================================================
        case QUIC_STREAM_EVENT_CANCEL_ON_LOSS:{
            return QUIC_STATUS_SUCCESS;
        }
        // ============================================================================
        // EVENT: 
        // ============================================================================
        default:{
            return QUIC_STATUS_SUCCESS;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
msquic_connect_callback(
    _In_ HQUIC ConnectionHandle,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    session_t* session = (session_t*)Context;
    assert(session);
    CLIENT_QUIC_CONTEXT *MsQuic = session->MsQuic;
    assert(MsQuic);
    assert(MsQuic->ConnectionHandle);

    UNREFERENCED_PARAMETER(ConnectionHandle);

    switch (Event->Type) {

    // =====================================================================
    // EVENT: DATAGRAM SEND STATE CHANGED
    // =====================================================================
    case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {

        pkt_data_t* pkt = Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
        if (!pkt) {
            return QUIC_STATUS_SUCCESS;
        }
    
        switch (Event->DATAGRAM_SEND_STATE_CHANGED.State) {
            case QUIC_DATAGRAM_SEND_SENT:
                if (pkt != NULL) {
                    pool_put(pkt);
                }
                break;

            case QUIC_DATAGRAM_SEND_LOST_SUSPECT:
            case QUIC_DATAGRAM_SEND_LOST_DISCARDED:
                // Telemetry / Metrics only
                break;

            case QUIC_DATAGRAM_SEND_ACKNOWLEDGED:
            case QUIC_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS:
                // Telemetry / Metrics only
                break;

            case QUIC_DATAGRAM_SEND_CANCELED:
                if (pkt != NULL) {
                    pool_put(pkt);
                }
                break;

            default:
                break;
            }
        return QUIC_STATUS_SUCCESS;
    }

    // =====================================================================
    // EVENT: DATAGRAM RECEIVED
    // =====================================================================
    case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {

        if (!Event->DATAGRAM_RECEIVED.Buffer->Buffer) {
            return QUIC_STATUS_SUCCESS;
        }

        if (Event->DATAGRAM_RECEIVED.Buffer->Length == 0) {
            return QUIC_STATUS_SUCCESS;
        }

        pkt_data_t *pkt = (pkt_data_t* )pool_try_get(session->pool_pkt_data_recv);
        if (!pkt) {
            return QUIC_STATUS_SUCCESS;
        }

        pkt->buf.Buffer = pkt->data;
        pkt->buf.Length = Event->DATAGRAM_RECEIVED.Buffer->Length;

        memcpy(pkt->data, Event->DATAGRAM_RECEIVED.Buffer->Buffer, pkt->buf.Length);
        queue_try_push(session->queue_pkt_data_recv, pkt);

        return QUIC_STATUS_SUCCESS;
    }

    // =====================================================================
    // EVENT: RESUMPTION TICKET RECEIVED
    // =====================================================================
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:

        if (MsQuic->ResumptionTicketBuffer != NULL) {
            free(MsQuic->ResumptionTicketBuffer);
            MsQuic->ResumptionTicketBuffer = NULL;
            MsQuic->ResumptionTicketLength = 0;
        }

        MsQuic->ResumptionTicketLength = 
            Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength;
        MsQuic->ResumptionTicketBuffer = 
            (uint8_t*)malloc(Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        
        if (!MsQuic->ResumptionTicketBuffer) {
            LOG_ERROR("Failed to allocate memory for resumption ticket");
            return QUIC_STATUS_OUT_OF_MEMORY;
        }

        memcpy(MsQuic->ResumptionTicketBuffer, 
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket, 
                Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        
        LOG_DEBUG("QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED");

        return QUIC_STATUS_SUCCESS;

    // =====================================================================
    // EVENT: DATAGRAM STATE CHANGED
    // =====================================================================
    case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {
        LOG_DEBUG("Datagram state changed: SendEnabled=%d, MaxSendLength=%u",
                Event->DATAGRAM_STATE_CHANGED.SendEnabled,
                Event->DATAGRAM_STATE_CHANGED.MaxSendLength);
        return QUIC_STATUS_SUCCESS;
    }

    // =====================================================================
    // EVENT: CONNECTED
    // =====================================================================
    case QUIC_CONNECTION_EVENT_CONNECTED:
        // Connection successfull
        state_sync_set(&session->con_state, SESSION_CONNECTED);
        LOG_DEBUG("QUIC_CONNECTION_EVENT_CONNECTED");

        return QUIC_STATUS_SUCCESS;

    // =====================================================================
    // EVENT: SHUTDOWN INITIATED BY TRANSPORT
    // =====================================================================
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        // Transport-level shutdown (e.g., network error)
        LOG_WARNING("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT: code=%llu", 
            (unsigned long long)Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode);
        return QUIC_STATUS_SUCCESS;

    // =====================================================================
    // EVENT: SHUTDOWN INITIATED BY PEER
    // =====================================================================
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        // Peer initiated shutdown
        LOG_WARNING("QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: code=%llu", 
            (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
                 
        return QUIC_STATUS_SUCCESS;

    // =====================================================================
    // EVENT: SHUTDOWN COMPLETE
    // =====================================================================
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        state_sync_set(&session->con_state, SESSION_DISCONNECTED);

        MsQuic->ConnectionHandle = NULL;

        if (ConnectionHandle) {
            MsQuic->Api->ConnectionClose(ConnectionHandle);
        }

        LOG_DEBUG("QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE");

        return QUIC_STATUS_SUCCESS;

    default:
        LOG_WARNING("QUIC Connection Event->UNKNOWN, event type: %u", Event->Type);
        break;
    }

    return QUIC_STATUS_SUCCESS;
}

CLIENT_QUIC_CONTEXT *MsQuicCreate() {
        
    CLIENT_QUIC_CONTEXT *MsQuic = (CLIENT_QUIC_CONTEXT*)calloc(1, sizeof(CLIENT_QUIC_CONTEXT));
    if (!MsQuic) {
        LOG_ERROR("Memory allocation failed");
        return NULL;
    }

    return MsQuic;
}

int MsQuicRegister(CLIENT_QUIC_CONTEXT *MsQuic, const char *app_name, int exec_profile)
{
    if (!MsQuic || !app_name) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuicOpen2(&MsQuic->Api);

    if (QUIC_FAILED(Status)) {
        LOG_ERROR("MsQuicOpen2() failed, Status: 0x%x!", Status);
        return -ECANCELED;
    }

    MsQuic->RegConfig.AppName = app_name;
    MsQuic->RegConfig.ExecutionProfile = (QUIC_EXECUTION_PROFILE)exec_profile;

    Status = MsQuic->Api->RegistrationOpen(
        &MsQuic->RegConfig, 
        &MsQuic->Registration
    );
    
    if (QUIC_FAILED(Status)) {
        LOG_ERROR("RegistrationOpen() failed, Status: 0x%x!", Status);
        return -ECANCELED;
    }

    return 0;

}

int MsQuicConfigAddr(CLIENT_QUIC_CONTEXT *MsQuic, const char* local_addr, const char* server_addr, uint16_t server_port) {

    if (!MsQuic || !local_addr || !server_addr) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    memset(&MsQuic->ServerAddr, 0, sizeof(MsQuic->ServerAddr));


    if (!QuicAddrFromString(
                server_addr, 
                server_port, 
                &MsQuic->ServerAddr))
    {
        LOG_ERROR("Network: The provided server addr is invalid: [%s]", server_addr);
        return -EINVAL;
    }
    int si_family = QuicAddrGetFamily(&MsQuic->ServerAddr);
    if (si_family != AF_INET) {
        LOG_ERROR("Network: The provided server addr family is not supported: [%d]", si_family);
        return -EINVAL;
    }
    QuicAddrSetPort(&MsQuic->ServerAddr, server_port);


    memset(&MsQuic->LocalAddr, 0, sizeof(MsQuic->LocalAddr));
    if (!QuicAddrFromString(
                local_addr, 
                0, 
                &MsQuic->LocalAddr))
    {
        LOG_ERROR("Network: The provided local addr is invalid: [%s]", server_addr);
        return -EINVAL;
    }
    si_family = QuicAddrGetFamily(&MsQuic->LocalAddr);
    if (si_family != AF_INET) {
        LOG_ERROR("Network: The provided local addr family is not supported: [%d]", si_family);
        return -EINVAL;
    }
    QuicAddrSetPort(&MsQuic->LocalAddr, 0);
    return 0;
}

int MsQuicConfigParameters(CLIENT_QUIC_CONTEXT *MsQuic, const char* alpn)
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
    MsQuic->Settings.DisconnectTimeoutMs = 2 * 60 * 1000;
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

    // For VPN tunneling use unreliable datagram (read TCP meltdown)
    bool unreliable = true;

    if (unreliable) {
        MsQuic->Settings.DatagramReceiveEnabled = 1;
        MsQuic->Settings.IsSet.DatagramReceiveEnabled = 1;

        // 3. Set Max MTU to align with physical eth0 limits (1500 bytes)        
        MsQuic->Settings.MaximumMtu = 1480;
        MsQuic->Settings.IsSet.MaximumMtu = 1;
        // IPv6 baseline minimum
        MsQuic->Settings.MinimumMtu = 1280; 
        MsQuic->Settings.IsSet.MinimumMtu = 1;
    }

    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuic->Api->ConfigurationOpen(
        MsQuic->Registration, 
        &MsQuic->Alpn, 1, 
        &MsQuic->Settings, 
        sizeof(QUIC_SETTINGS), 
        NULL, 
        &MsQuic->Configuration
    );
    
    if (QUIC_FAILED(Status)) {
        LOG_ERROR("MsQuic Api ConfigurationOpen() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }
    
    return 0;
}

int MsQuicConfigCredentials(CLIENT_QUIC_CONTEXT *MsQuic) {

    if (!MsQuic) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    memset(&MsQuic->CredConfig, 0, sizeof(MsQuic->CredConfig));
    MsQuic->CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    MsQuic->CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
        
    bool unsecure = true;

    if (unsecure) {
        MsQuic->CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuic->Api->ConfigurationLoadCredential(
        MsQuic->Configuration, 
        &MsQuic->CredConfig
    );

    if (QUIC_FAILED(Status)) {
        LOG_ERROR("MsQuic Api ConfigurationLoadCredential() failed, QuicStatus: 0x%x!", Status);
        return -ECANCELED;
    }

    return 0;
}



int MsQuicConnectionStart(CLIENT_QUIC_CONTEXT *MsQuic, session_t *session)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuic->Api->ConnectionOpen(
        MsQuic->Registration,
        msquic_connect_callback,
        session,
        &MsQuic->ConnectionHandle
    );

    if (QUIC_FAILED(Status)) {
        LOG_ERROR("ConnectionOpen failed: 0x%x", Status);
        return -ECONNABORTED;
    }

    // Apply the saved client local bind address configuration
    Status = MsQuic->Api->SetParam(
        MsQuic->ConnectionHandle,
        QUIC_PARAM_CONN_LOCAL_ADDRESS,
        sizeof(MsQuic->LocalAddr),
        &MsQuic->LocalAddr
    );
    
    if (QUIC_FAILED(Status)) {
        MsQuic->Api->ConnectionClose(MsQuic->ConnectionHandle);
        MsQuic->ConnectionHandle = NULL;
        LOG_ERROR("SetParam(LOCAL_ADDRESS) failed with status: %d", Status);
        return -ECONNABORTED;
    }

    // STEP 3: Configure its remote destination address
    Status = MsQuic->Api->SetParam(
        MsQuic->ConnectionHandle,
        QUIC_PARAM_CONN_REMOTE_ADDRESS,
        sizeof(MsQuic->ServerAddr),
        &MsQuic->ServerAddr
    );

    if (QUIC_FAILED(Status)) {
        MsQuic->Api->ConnectionClose(MsQuic->ConnectionHandle);
        MsQuic->ConnectionHandle = NULL;
        LOG_ERROR("SetParam(QUIC_PARAM_CONN_REMOTE_ADDRESS) failed: 0x%x", Status);
        return -ECONNABORTED;
    }

    uint16_t server_port = QuicAddrGetPort(&MsQuic->ServerAddr);

    // STEP 4: Fire off the wire handshake using the stored configuration
    Status = MsQuic->Api->ConnectionStart(
        MsQuic->ConnectionHandle,
        MsQuic->Configuration,
        QUIC_ADDRESS_FAMILY_UNSPEC,
        NULL,
        server_port
    );
    
    if (QUIC_FAILED(Status)) {
        MsQuic->Api->ConnectionClose(MsQuic->ConnectionHandle);
        MsQuic->ConnectionHandle = NULL;
        LOG_ERROR("ConnectionStart() Error");
        return -ECONNABORTED;
    }

    state_sync_set(&session->con_state, SESSION_CONNECTING);

    if(state_sync_wait_ms_abort(&session->con_state, SESSION_CONNECTED, SESSION_DISCONNECTED, 5000) != 0) {
        LOG_ERROR("Connection TIMEOUT");
        return -ETIMEDOUT;
    }

    LOG_DEBUG("Connection start issued");

    return 0;
}

int MsQuicStreamStart(CLIENT_QUIC_CONTEXT *MsQuic, session_t *session)
{  
    if (!state_sync_check(&session->con_state, SESSION_CONNECTED)) {
        return -ECONNABORTED;
    }
    
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    Status = MsQuic->Api->StreamOpen(
        MsQuic->ConnectionHandle,
        QUIC_STREAM_OPEN_FLAG_NONE,
        msquic_stream_callback,
        session,
        &MsQuic->StreamHandle);

    if (QUIC_FAILED(Status)) {
        fprintf(stderr, "[DEBUG] Failed to StreamOpen for control channel (status: %d\n", Status);
        state_sync_set(&session->stream_state, STREAM_CLOSED);
        return -ECONNABORTED;
    }

    Status = MsQuic->Api->StreamStart(
        MsQuic->StreamHandle,
        QUIC_STREAM_START_FLAG_IMMEDIATE);

    if (QUIC_FAILED(Status)) {
        MsQuic->Api->StreamClose(MsQuic->StreamHandle);
        MsQuic->StreamHandle = NULL;
        fprintf(stderr, "[DEBUG] Failed to StreamStart for control channel (status: %d\n", Status);
        state_sync_set(&session->stream_state, STREAM_CLOSED);
        return -ECONNABORTED;
    }

    state_sync_set(&session->stream_state, STREAM_OPENING);

    if(state_sync_wait_ms_abort(&session->stream_state, STREAM_OPEN, STREAM_CLOSED, 5000) != 0) {    
        return -ETIMEDOUT;
    }

    LOG_DEBUG("Stream open successfully");

    return 0;
}

int MsQuicStreamSend(CLIENT_QUIC_CONTEXT* MsQuic, uint8_t *buf, size_t len)
{
    assert(MsQuic);
    assert(buf);
    assert(len > 0);

    uint8_t *out_buf = (uint8_t*)malloc(len);
    if (!out_buf) {
        MsQuic->Api->StreamShutdown(
                MsQuic->StreamHandle, 
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 
                0);
        return -ENOMEM;
    }
    memcpy(out_buf, buf, len);

    QUIC_BUFFER* quic_buf = malloc(sizeof(QUIC_BUFFER));
    quic_buf->Buffer = out_buf;
    quic_buf->Length = (uint32_t)len;

    QUIC_STATUS Status = MsQuic->Api->StreamSend(
        MsQuic->StreamHandle,
        quic_buf,
        1,
        QUIC_SEND_FLAG_NONE,
        quic_buf
    );

    if (QUIC_FAILED(Status)) {
        LOG_ERROR("StreamSend failed, 0x%x", Status);
        free(quic_buf->Buffer);
        free(quic_buf);
        MsQuic->Api->StreamShutdown(
            MsQuic->StreamHandle, 
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 
            0
        );
        return -ECANCELED;
    }

    return 0;
}

int MsQuicShutdown(CLIENT_QUIC_CONTEXT *MsQuic) {
    
    if (!MsQuic) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    if (MsQuic->Api != NULL) {
        if (MsQuic->ConnectionHandle != NULL) {
            MsQuic->Api->ConnectionClose(MsQuic->ConnectionHandle);
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

