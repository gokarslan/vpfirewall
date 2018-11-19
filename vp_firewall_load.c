#include "vp_firewall_load.h"


int load_rules(rule_t **heads, const char *config_path) {

    FILE *fp = fopen(config_path, "r");
    if (fp == NULL) {
        printf("Could not open the configuration file %s.", config_path);
        return 1;
    }
    rule_t *nexts[CHAIN_SIZE];
    nexts[INPUT] = heads[INPUT];
    nexts[OUTPUT] = heads[OUTPUT];
    nexts[FORWARD] = heads[FORWARD];
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    /* Read the configuration file line by line and add the rules the rule list */
    while ((read = getline(&line, &len, fp)) != -1) {
        add_rule(nexts, line);
    }
    if (line) {
        free(line);
    }
    fclose(fp);
    return 0;
}

int add_rule(rule_t **nexts, const char *line) {
    rule_t *next = calloc(1, sizeof(rule_t));
    char param[BUFFER_SIZE];
    int start_index = -1;
    while ((start_index = get_next_param(line, start_index, param)) != -1) {
        //int opt = parse_param(param);
        if (strcmp(param, "-A") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                // TODO: do not allow having two APPEND in one rule.
                if (strcmp(param, "INPUT") == 0) {
                    if (nexts[INPUT] != NULL) {
                        nexts[INPUT]->next = next;
                    }
                    nexts[INPUT] = next;
                } else if (strcmp(param, "OUTPUT") == 0) {
                    if (nexts[OUTPUT] != NULL) {
                        nexts[OUTPUT]->next = next;
                    }
                    nexts[OUTPUT] = next;
                } else if (strcmp(param, "FORWARD") == 0) {
                    if (nexts[FORWARD] != NULL) {
                        nexts[FORWARD]->next = next;
                    }
                    nexts[FORWARD]->next = next;
                    nexts[FORWARD] = next;
                }
            } else {
                printf("-A needs to follow INPUT, OUTPUT or FORWARD.\n");
                return 1;
            }
        } else if (strcmp(param, "-p") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (strcmp(param, "tcp") == 0) {
                    next->protocol = TCP;
                } else if (strcmp(param, "udp") == 0) {
                    next->protocol = UDP;
                } else if (strcmp(param, "icmp") == 0) {
                    next->protocol = ICMP;
                } else {
                    printf("-p defines an unknown protocol %s, vpFirewall supports TCP, UDP or ICMP.\n", param);
                    return 1;
                }

            } else {
                printf("-p needs to follow a protocol from TCP, UDP or ICMP.\n");
                return 1;
            }

        } else if (strcmp(param, "--sport") == 0 || strcmp(param, "--source-port") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                next->source_port = atoi(param);
            } else {
                printf("--sport needs to follow a port number.\n");
                return 1;
            }

        } else if (strcmp(param, "--dport") == 0 || strcmp(param, "--destination-port") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                next->dest_port = atoi(param);
            } else {
                printf("--sport needs to follow a port number.\n");
                return 1;
            }

        } else if (strcmp(param, "--source") == 0 || strcmp(param, "-s") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (set_ip_address(&(next->source_ip), &(next->source_ip_mask), param) != 0) {
                    //printf("--source follows an invalid IP address %s.\n", param);
                    return 1;
                }
            } else {
                printf("--source needs to follow an IP address.\n");
                return 1;
            }

        } else if (strcmp(param, "--destination") == 0 || strcmp(param, "-d") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (set_ip_address(&(next->dest_ip), &(next->dest_ip_mask), param) != 0) {
                    //printf("--destination follows an invalid IP address %s.\n", param);
                    return 1;
                }
            } else {
                printf("--source needs to follow an IP address.\n");
                return 1;
            }

        } else if (strcmp(param, "--mac-source") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (set_mac_address(&(next->source_mac), param) != 0) {
                    //printf("--mac-source follows an invalid MAC address %s.\n", param);
                    return 1;
                }
            } else {
                printf("--mac-source needs to follow a MAC address.\n");
                return 1;
            }

        } else if (strcmp(param, "--mac-destination") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (set_mac_address(&(next->dest_mac), param) != 0) {
                    //printf("--mac-destination follows an invalid MAC address %s.\n", param);
                    return 1;
                }
            } else {
                printf("--mac-destination needs to follow a MAC address.\n");
                return 1;
            }

        } else if (strcmp(param, "--match") == 0 || strcmp(param, "-m") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (strcmp(param, "tcp") == 0) {

                } else if (strcmp(param, "mac") == 0) {

                } else {
                    printf("--match follows an unknown match type %s\n", param);
                    return 1;
                }

            } else {
                printf("--match needs to follow a match type from the list TCP, UDP, ICMP, MAC\n");
                return 1;
            }
        } else if (strcmp(param, "-j") == 0) {
            if ((start_index = get_next_param(line, start_index, param)) != -1) {
                if (strcmp(param, "ACCEPT") == 0) {
                    next->action = ACCEPT;
                } else if (strcmp(param, "DROP") == 0) {
                    next->action = DROP;
                } else if (strcmp(param, "REJECT") == 0) {
                    next->action = REJECT;
                } else {
                    printf("-j follows an unknown action %s.\n", param);
                    return 1;
                }
            } else {
                printf("-j needs to follow an action from the list ACCEPT, DROP or REJECT.\n");
                return 1;
            }

        } else if (strcmp(param, "-4") == 0 || strcmp(param, "--ipv4") == 0) {
            next->is_ipv6 = 0;
        } else if (strcmp(param, "-6") == 0 || strcmp(param, "--ipv6") == 0) {
            next->is_ipv6 = 1;
        } else {
            printf("Unknown parameter in the configuration %s.\n", param);
            return 1;
        }

    }

    return 0;
}

int get_next_param(const char *line, int start_index, char *param) {
    int i;
    start_index++;
    for (i = start_index; line[i] && line[i] != ' ' && line[i] != '\n' && line[i] != '\t'; ++i) {
        param[i - start_index] = line[i];
    }
    param[i - start_index] = '\0';
    if (strlen(param) == 0) {
        return -1;
    }
    //printf("PARAM: %s\n", param);
    return i;

}

int set_ip_address(__int128 *ip_address, short *ip_mask, const char *param) {
    *ip_address = 0;
    *ip_mask = -1;
    int len = strlen(param);
    char segment[5];
    int segment_count = 0;
    int is_ip_v6 = -1;

    for (int i = 0; i < len; ++i) {
        if (param[i] == '.') {
            if (is_ip_v6 == 1) {
                printf("IPv6 address cannot have . in it.\n");
                return 1;
            }
            segment[segment_count++] = '\0';
            is_ip_v6 = 0;
            *ip_address = *ip_address * 256 + atoi(segment);
            segment_count = 0;
        } else if (param[i] == ':') {
            if (is_ip_v6 == 0) {
                printf("IPv4 address cannot have : in it.\n");
                return 1;
            }
            segment[segment_count++] = '\0';
            is_ip_v6 = 1;
            *ip_address = *ip_address * 65536 + strtol(segment, NULL, 16);
            segment_count = 0;
        } else if (param[i] == '/') {
            segment[segment_count++] = '\0';
            if (is_ip_v6 == 0) {
                *ip_address = *ip_address * 256 + atoi(segment);
                segment_count = 0;

            } else if (is_ip_v6 == 1) {
                *ip_address = *ip_address * 65536 + strtol(segment, NULL, 16);
                segment_count = 0;

            } else {
                printf("Unknown IP version %s\n", param);
                return 1;
            }
            *ip_mask = 0;
        } else {
            segment[segment_count++] = param[i];
        }
    }
    if (segment_count == 0) {
        printf("Invalid IP address %s\n", param);
        return 1;
    }
    if (*ip_mask == 0) {
        *ip_mask = atoi(segment);
    } else if (is_ip_v6 == 0) {
        *ip_address = *ip_address * 256 + atoi(segment);
        *ip_mask = 0;

    } else if (is_ip_v6 == 1) {
        *ip_address = *ip_address * 65536 + strtol(segment, NULL, 16);
        *ip_mask = 0;

    } else {
        printf("Unknown IP version %s\n", param);
        return 1;
    }
    return 0;


}

int set_mac_address(__int64 *mac_address, const char *param) {
    char segment[3];
    int segment_count = 0;
    if (strlen(param) != MAC_ADDR_SIZE) {
        printf("Invalid mac address %s, it needs to be in a format FF:FF:FF:FF:FF:FF\n", param);
        return 1;
    }
    for (int i = 0; i < MAC_ADDR_SIZE + 1; ++i) {
        if (i % 3 == 2) {
            if (i != MAC_ADDR_SIZE && param[i] != ':') {
                printf("Invalid mac address %s, it needs to be in a format FF:FF:FF:FF:FF:FF\n", param);

                return 1;
            }
            segment[segment_count++] = '\0';
            *mac_address = *mac_address * 256 + strtol(segment, NULL, 16);
            segment_count = 0;
        } else {
            segment[segment_count++] = param[i];
        }
    }
    return 0;
}

void print_rules(rule_t *head) {

    struct rule *next;
    for (rule_t *next = head; next != NULL; next = next->next) {
        printf("Type: ");
        switch (next->type) {
            case FILTER:
                printf("FILTER\n");
                break;
            case NAT:
                printf("NAT\n");
                break;
            case MANGLE:
                printf("MANGLE\n");
                break;
            default:
                printf("Unknown %d\n", next->type);
        }

        printf("Protocol: ");
        switch (next->protocol) {
            case TCP:
                printf("TCP\n");
                break;
            case UDP:
                printf("UDP\n");
                break;
            case ICMP:
                printf("ICMP\n");
                break;
            case OTHER:
                printf("OTHER\n");
                break;
            default:
                printf("Unknown %d\n", next->protocol);
        }
        if (next->source_mac != 0) {
            printf("Source MAC: %d\n", next->source_mac);
        }
        if (next->dest_mac != 0) {
            printf("Destination MAC: %d\n", next->dest_mac);
        }
        if (next->source_ip != 0) {
            printf("Source IP: %d/%d\n", next->source_ip, next->source_ip_mask);
        }
        if (next->dest_ip != 0) {
            printf("Destination IP: %d/%d\n", next->dest_ip, next->dest_ip_mask);
        }
        if (next->source_port != 0) {
            printf("Source port: %d\n", next->source_port);
        }
        if (next->dest_port != 0) {
            printf("Destination port: %d\n", next->dest_port);
        }
        printf("IP version: ");
        if (next->is_ipv6 == 0) {
            printf("IPv4\n");
        } else if (next->is_ipv6 == 1) {
            printf("IPv6\n");
        } else {
            printf("Unknown %d\n", next->is_ipv6);
        }
        printf("Action: ");

        switch (next->action) {
            case ACCEPT:
                printf("ACCEPT\n");
                break;
            case DROP:
                printf("DROP\n");
                break;
            case REJECT:
                printf("REJECT\n");
                break;
            default:
                printf("Unknown %d\n", next->action);
        }
        printf("----------------------------------------\n");

    }
}

int main() {
    rule_t *heads[CHAIN_SIZE];
    load_rules(heads, "vp_firewall.conf");

    printf("INPUT chain:\n");
    printf("----------------------------------------\n");
    print_rules(heads[INPUT]);
    printf("----------------------------------------\n");

    printf("OUTPUT chain:\n");
    printf("----------------------------------------\n");
    print_rules(heads[OUTPUT]);
    printf("----------------------------------------\n");

    printf("FORWARD chain:\n");
    printf("----------------------------------------\n");
    print_rules(heads[FORWARD]);
    printf("----------------------------------------\n");


}