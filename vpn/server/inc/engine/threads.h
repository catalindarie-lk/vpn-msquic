#ifndef THREADS_H
#define THREADS_H

#ifdef __cplusplus
extern "C" {
#endif

void* thread_pkt_data_send(void* arg);

void* thread_pkt_data_recv(void* arg);

#ifdef __cplusplus
}
#endif

#endif