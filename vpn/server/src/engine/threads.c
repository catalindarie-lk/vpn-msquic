
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <poll.h>

#include "log.h"
#include "queue.h"
#include "session.h"
#include "quic.h"
#include "pkt_data.h"
#include "ip_pool.h"
#include "client.h"
#include "threads.h"

// Thread that process datagrams received from outside with destination to the client via the tunnel
void* thread_pkt_data_send(void* arg)
{
    session_t* session = (session_t*)arg;
    assert(session);

    state_sync_wait(&session->tun_state,  TUN_READY);

    struct pollfd fds[2];

    tun_get_fd(session->tun, &fds[0].fd);
    fds[0].events = POLLIN;

    fds[1].fd = session->shutdown_fd;  // Watch shutdown event handle
    fds[1].events = POLLIN;
    
    while (session->running_pkt_data_send) {

        int ret = poll(fds, 2, -1);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        // 1. Check for Shutdown Signal
        if (fds[1].revents & POLLIN) {
            LOG_DEBUG("Read thread received shutdown signal.");
            break; // Exit thread loop cleanly
        }

        if (fds[0].revents & POLLIN) {

            pkt_data_t* pkt = (pkt_data_t* )pool_wait_get(session->pool_pkt_data_send);

            int tun_fd = -1; 
            tun_get_fd(session->tun, &tun_fd);
            ssize_t bytes_read = read(tun_fd, pkt->data, sizeof(pkt->data));
            if (bytes_read < 0) {
                // Optional non-fatal retry logic:
                // if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                //     continue;
                // }
                LOG_WARNING("read() error from TUN descriptor (errno: %d)", errno);
                pool_put(pkt);
                break;
            }

            struct in_addr src_addr, dest_addr;
            if (pkt_data_iphdr((uint8_t*)pkt->data, bytes_read, &src_addr, &dest_addr) !=0) {
                pool_put(pkt);
                continue;
            }

            client_t* client =  ip_client_search(session->ip_pool, &dest_addr);
            if (!client) {
                pool_put(pkt);
                continue;
            }

            pkt_data_print(client->uid, true, (uint8_t*)pkt->data, bytes_read);
            
            if (!session->MsQuic) {
                LOG_ERROR("MsQuic not initialized");
                continue;
            }

            if (!session->MsQuic->Api) {
                LOG_ERROR("MsQuic->Api not initialized");
                continue;
            }

            pkt->buf.Buffer = (uint8_t*)pkt->data;
            pkt->buf.Length = (uint32_t)bytes_read;

            // Send encapsulated IP frame down MSQuic datagram stream
            QUIC_STATUS Status = session->MsQuic->Api->DatagramSend(
                    client->ConnectionHandle,
                    &pkt->buf,
                    1,
                    QUIC_SEND_FLAG_NONE,
                    pkt
            );

            if (QUIC_FAILED(Status)) {
                pool_put(pkt);
                LOG_ERROR("Quic DatagramSend failed with status: 0x%x", Status);
            }
        }

    }
    LOG_DEBUG("------------THREAD joined-------------");
    return NULL;
}

// Thread that process datagrams received via the tunnel from a client
void* thread_pkt_data_recv(void* arg)
{
    session_t* session = (session_t*)arg;

    state_sync_wait(&session->tun_state,  TUN_READY);

    while (session->running_pkt_data_recv) {

        pkt_data_t* pkt = (pkt_data_t* )queue_wait_pop(session->queue_pkt_data_recv);
        if (!pkt)  {
            // sentinel for thread joining
            break;
            // continue;
        }

        struct in_addr src_addr, dest_addr;
        if (pkt_data_iphdr((uint8_t*)pkt->buf.Buffer, pkt->buf.Length, &src_addr, &dest_addr) !=0) {
            pool_put(pkt);
            continue;
        }

        client_t* client = ip_client_search(session->ip_pool, &src_addr);
        if (client) {
            pkt_data_print(client->uid, false, (uint8_t*)pkt->buf.Buffer, pkt->buf.Length);
        }

        int tun_fd = -1; 
        tun_get_fd(session->tun, &tun_fd);
        ssize_t bytes_written = write(tun_fd, pkt->buf.Buffer, pkt->buf.Length);
        if (bytes_written < 0) {
            perror("write(tun_fd) failed");
        }
        pool_put(pkt);
    }

    LOG_DEBUG("------------THREAD joined-------------");
    return NULL;
}

