#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <net/if.h>


#define MAX_HOST_NAME (255)
#define MAX_MSQUIC_APP_NAME (64)

// Configuration parameters bound from CLI inputs or UI text fields
typedef struct vpn_config_t {
    char server_hostname[MAX_HOST_NAME];
    uint16_t server_port;
} vpn_config_t;


#endif