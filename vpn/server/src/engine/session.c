

#include "session.h"
#include "pool.h"
#include "queue.h"
#include "pkt_data.h"

session_t* create_session()
{
    session_t* session = (session_t* )malloc(sizeof(session_t));
    if (!session) return NULL;

    memset(session, 0, sizeof(session_t));

    atomic_init(&session->client_cnt, 1);

    assert (state_sync_init(&session->tun_state, TUN_CLOSED) == 0);

    session->shutdown_fd = eventfd(0, EFD_NONBLOCK);

    pool_t *pool_pkt_data_send = NULL;
    pool_t *pool_pkt_data_recv = NULL;
    queue_t *queue_pkt_data_recv = NULL;

    pool_pkt_data_send = pool_init(sizeof(pkt_data_t), 0);
    if(!pool_pkt_data_send) {
        goto cleanup;
    }
    session->pool_pkt_data_send = pool_pkt_data_send;

    pool_pkt_data_recv = pool_init(sizeof(pkt_data_t), 0);
    if(!pool_pkt_data_recv) return NULL;
    session->pool_pkt_data_recv = pool_pkt_data_recv;

    queue_pkt_data_recv = queue_init(128 * 1024 * 1024);
    if(!queue_pkt_data_recv) return NULL;
    session->queue_pkt_data_recv = queue_pkt_data_recv;

    return session;

cleanup:

    pool_destroy(pool_pkt_data_send);
    pool_destroy(pool_pkt_data_recv);
    queue_destroy(queue_pkt_data_recv);
    free(session);
    return NULL;


}

