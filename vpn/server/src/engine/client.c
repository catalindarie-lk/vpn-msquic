

#include <stdatomic.h>
#include <errno.h>

#include "log.h"
#include "client.h"
#include "session.h"

client_t* list_add_client(session_t *session, HQUIC ConnectionHandle) {

    pthread_mutex_lock(&session->client_list_lock);
    for (int idx = 0; idx < session->ip_pool->max_clients; idx++) {            
        if (session->client_list[idx] == NULL) {
            
            client_t* client = pool_try_get(session->client_pool);
            if (!client) {
                break;
            }

            client->slot_idx = idx;
            client->ConnectionHandle = ConnectionHandle;
            client->session = session;

            // client->uid = atomic_fetch_add_explicit(&session->client_cnt, 1, memory_order_acq_rel);
            // the uid is assigned in QUIC_CONNECTION_EVENT_CONNECTED when resumption ticket is evaluated
            // TODO - maybe this should be moved to event connected?

            // In MsQuic, you should allocate your custom client session state during QUIC_LISTENER_EVENT_NEW_CONNECTION, not on CONNECTED.
            // Here is why:
            // 1. Lifetime & Context Ownership
            // NEW_CONNECTION is the moment MsQuic hands you the handle for the incoming HQUIC Connection.
            // To track state for that connection (buffers, sequence numbers, user context), 
            // you need to assign your allocated struct to the connection's context pointer immediately,
            // using MsQuic->SetContext(Connection, ClientSession).
            // If you wait until QUIC_CONNECTION_EVENT_CONNECTED, events can race or 
            // you will have no place to store early session context if you need to 
            // set up stream handlers or settings prior to handshaking completing.

            // 2. Early Event Flow & Pre-Connection Setup
            // Before QUIC_CONNECTION_EVENT_CONNECTED ever fires, 
            // you often need to configure parameters on the incoming 
            // connection inside the NEW_CONNECTION callback:

            // Registering the connection's event callback function via MsQuic->SetCallbackHandler().

            // Setting connection-level configuration or TLS/certificate parameters 
            // (MsQuic->SetParam / MsQuic->ConfigurationLoadCredential).

            // If allocation fails during NEW_CONNECTION, 
            // you can return QUIC_STATUS_OUT_OF_MEMORY immediately to 
            // reject the handshake before wasting system or crypto resources.

            client->ip_entry = NULL;
            session->client_list[idx] = client;
            pthread_mutex_unlock(&session->client_list_lock);
            return client;
        }
    }
    pthread_mutex_unlock(&session->client_list_lock);
    return NULL;
}


int initialize_client_state(client_t* client) {
    
    assert(client);
    session_t* session = client->session;
    assert(session);

    client->ip_entry = ip_acquire(session->ip_pool, client);
    if (!client->ip_entry) {
        LOG_WARNING("Rejecting connection due to server full (no virtip available)");
        return -1;
    }

    client->uid = atomic_fetch_add_explicit(&session->client_cnt, 1, memory_order_relaxed);

    return 0;
}

// TODO -> handle session resumption based on resumption ticket
// at the moment it is just creating a new client
// more data can be included in the resumption ticket when sent at client
// during TLS handshake and then this data can be used to restore the session
// e.g assigned tunneling ip
int restore_client_state(client_t* client, uint64_t uid) {
    
    assert(client);
    session_t* session = client->session;
    assert(session);

    client->uid = uid;
    client->ip_entry = NULL;

    return 0;
}

int list_remove_client(session_t *session, client_t *client) {
    
    if (!session) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }
    if (!client) {
        LOG_ERROR("Invalid parameter");
        return -EINVAL;
    }

    if (client->slot_idx < 0 || client->slot_idx > session->ip_pool->max_clients) {
        LOG_WARNING("Trying to remove client out of list range");
        return -ERANGE;
    }
    
    if (client->uid > 0 && client->ip_entry) {
        LOG_DEBUG("Removed client UID [%d] with assigned IP [%s]", client->uid, client->ip_entry->ip_str);
    }

    client->slot_idx = 0;
    client->uid = 0;
    client->ip_entry = NULL;
    pthread_mutex_lock(&session->client_list_lock);
    session->client_list[client->slot_idx] = NULL;
    pthread_mutex_unlock(&session->client_list_lock);
    pool_put(client);
    return 0;
}

client_t *list_find_client_by_uid(session_t *session, uint64_t uid) {
    
    if (!session) {
        LOG_ERROR("Invalid parameter");
        errno = -EINVAL;
        return NULL;

    }
    if (!session->client_list) {
        LOG_ERROR("Client list not initialized");
        errno = -EINVAL;
        return NULL;
    }

    if (uid == 0) {
        LOG_DEBUG("Client UID not found in client list");
        return NULL;
    }

    client_t *found_client = NULL;

    pthread_mutex_lock(&session->client_list_lock);
    for (int i = 0; i < session->ip_pool->max_clients; i++) {
        client_t *client = session->client_list[i];
        if (client != NULL && client->uid == uid) {
            found_client = client;
            break;
        }
    }    
    pthread_mutex_unlock(&session->client_list_lock);
    return found_client;
}



