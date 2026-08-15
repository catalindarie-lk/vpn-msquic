#ifndef CLIENT_H
#define CLIENT_H

#include "msquic.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct session_t session_t;
typedef struct ip_entry_t ip_entry_t;

typedef struct client_t {
    HQUIC ConnectionHandle;
    session_t* session;
    int64_t uid;
    int slot_idx;
    ip_entry_t* ip_entry;
} client_t;

client_t* list_add_client(session_t *session, HQUIC ConnectionHandle);
int list_remove_client(session_t *session, client_t *client) ;

client_t *list_find_client_by_uid(session_t *session, uint64_t uid);

int initialize_client_state(client_t* client);

int restore_client_state(client_t* client, uint64_t uid);

#ifdef __cplusplus
}
#endif

#endif