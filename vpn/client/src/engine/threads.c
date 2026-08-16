/* 2. C Standard Library Headers */
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* 3. System, POSIX, and Linux Kernel Headers */
#include <error.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>

#include <sys/eventfd.h>
#include <poll.h>

/* 4. Third-Party Library Headers */
#include "log.h"
#include "msquic.h"

/* 5. Internal Project Headers */
#include "pkt_data.h"
#include "pool.h"
#include "quic.h"
#include "session.h"
#include "tun_api.h"

void* thread_pkt_data_send(void* arg)
{
    session_t *session = (session_t* )arg;
    assert(session);

    if(!state_sync_check(&session->tun_state, TUN_READY)) {
        LOG_ERROR("TUN interface NOT READY");
        return NULL;
    }

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

        // 2. Process TUN Packet (Guaranteed non-blocking read)
        if (fds[0].revents & POLLIN) {
            pkt_data_t* pkt = (pkt_data_t* )pool_wait_get(session->pool_pkt_data_send);
        

            int tun_fd = fds[0].fd;
            // tun_get_fd(session->tun, &tun_fd);

            ssize_t bytes_read = read(tun_fd, pkt->data, sizeof(pkt->data));
            if (bytes_read < 0) {
                perror("read() error from TUN descriptor");
                continue;
            }
                    
            pkt_data_print(0, false, (uint8_t*)pkt->data, bytes_read);        

            if (!state_sync_check(&session->con_state, SESSION_CONNECTED)) {
                pool_put(pkt);
                continue;
            }

            if (!session->MsQuic) {
                LOG_ERROR("MsQuic not initialized");
                continue;
            }

            if (!session->MsQuic->Api) {
                LOG_ERROR("MsQuic->Api not initialized");
                continue;
            }

            pkt->buf.Buffer = pkt->data;
            pkt->buf.Length = bytes_read;

            QUIC_STATUS Status = session->MsQuic->Api->DatagramSend(
                session->MsQuic->ConnectionHandle,
                &pkt->buf,
                1,
                QUIC_SEND_FLAG_NONE,
                pkt
            );

            if (QUIC_FAILED(Status)) {
                pool_put(pkt);
                LOG_ERROR("DatagramSend failed: 0x%x\n", Status);
            }

        }
    }

    LOG_DEBUG("thread_pkt_data_send() joined");

    return NULL;
}

// thread that receives data from the server via msquic and writes the data to tun0 for the client
void* thread_pkt_data_recv(void* arg)
{
    session_t* session = (session_t*)arg;
    assert(session);

    if(!state_sync_check(&session->tun_state, TUN_READY)) {
        LOG_ERROR("TUN interface NOT READY");
        return NULL;
    }

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
       
        pkt_data_print(0, true, (uint8_t*)pkt->buf.Buffer, pkt->buf.Length);

        int tun_fd = -1; 
        tun_get_fd(session->tun, &tun_fd);
        ssize_t bytes_written = write(tun_fd, pkt->buf.Buffer, pkt->buf.Length);
        if (bytes_written < 0) {
            perror("write(tun_fd) failed");
        }
        pool_put(pkt);
    }
    LOG_DEBUG("thread_pkt_data_recv() joined");

    return NULL;
}