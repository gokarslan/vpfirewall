//
// Created by Kerim Gökarslan on 11/18/18.
//

#ifndef VP_FIREWALL_LOAD_H
#define VP_FIREWALL_LOAD_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAC_ADDR_SIZE 17

#define CHAIN_SIZE 3
#define INPUT 0
#define OUTPUT 1
#define FORWARD 2

#define BUFFER_SIZE 8192


typedef long long __int64;


typedef enum type {
    FILTER, NAT, MANGLE
} type_t;
typedef enum protocol {
    TCP, UDP, ICMP, OTHER
} protocol_t;

typedef enum action {
    ACCEPT, DROP, REJECT
} action_t;

typedef struct rule {
    type_t type;
    protocol_t protocol;
    __int64 source_mac;
    __int64 dest_mac;
    __int128 source_ip;
    short source_ip_mask;
    __int128 dest_ip;
    short dest_ip_mask;
    short source_port;
    short dest_port;
    short is_ipv6;
    action_t action;

    struct rule *next;


} rule_t;


int load_rules(rule_t **heads, const char *config_path);

int add_rule(rule_t **nexts, const char *line);

int get_next_param(const char *line, int start_index, char *param);

int set_ip_address(__int128 *ip_address, short *ip_mask, const char *param);

int set_mac_address(__int64 *mac_address, const char *param);

#endif //VP_FIREWALL_LOAD_H