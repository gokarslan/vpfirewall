/**
 * This file implements a packet handler using packet_queue_t with pthread pool.
 */

#include "vp_firewall_pthread.h"

static rule_t **rules;
static struct nfq_q_handle *q_handle;

void process_ip_pkt(char *data, int ret) {
    struct iphdr *header = (struct iphdr *) data;
    if (header) {
        printf("%d\n", header->protocol);
    } else {
        printf("header is null!");
    }

}

static pthread_t *thread_pool;
static packet_queue_t *packet_queue;
/**
 * Checks if IPs are matching using CIDR.
 * @param ip1
 * @param ip2
 * @param ip_mask
 * @param is_ipv6
 * @return
 */
int is_ip_matching(__int128 ip1, __int128 ip2, short ip_mask, short is_ipv6) {
    __int128 denum = 1;
    int bits = is_ipv6 ? 128 : 32;
    if (ip_mask == -1) {
        ip_mask = bits;
    }
    for (int i = 0; i < bits - ip_mask; ++i) {
        denum *= 2;
    }
    return ip1 / denum == ip2 / denum;

}
/**
 * Handles L3 and L4 layer rules.
 * @param data
 * @param id
 * @return
 */
int handle_l3l4(char *data, int id) {
    /* Check IP rules */
    struct iphdr *ip_header = (struct iphdr *) data;
    __int128 source_ip = (__int128) ip_header->saddr;
    __int128 dest_ip = (__int128) ip_header->daddr;

    for (int i = 0; i < CHAIN_SIZE; ++i) {
        rule_t super_start;
        super_start.next = rules[i];


        rule_t *prev = &super_start;
        rule_t *current = &super_start;
        while (1) {
            current = current->next;
            if (current == NULL) {
                break;
            }
            if (current->source_ip != 0) {
                if (!is_ip_matching(source_ip, current->source_ip, current->source_ip_mask, current->is_ipv6)) {
                    //prev->next = current->next;
                    continue;
                }
            }
            if (current->dest_ip != 0) {
                if (!is_ip_matching(dest_ip, current->dest_ip, current->dest_ip_mask, current->is_ipv6)) {
                    //prev->next = current->next;
                    continue;
                }
            }
            if (current->protocol < OTHER && ip_header->protocol != current->protocol) {
                //prev->next = current->next;
                continue;
            }
            //printf("begin transport layer... %d\n", ip_header->protocol);
            int src_port = 0;
            int dest_port = 0;
            if (ip_header->protocol == UDP) {
                struct udphdr *udp_header = (struct udphdr *) (data + sizeof(struct iphdr));
                src_port = (unsigned int) ntohs(udp_header->source);
                dest_port = (unsigned int) ntohs(udp_header->dest);

            } else if (ip_header->protocol == TCP) {
                struct tcphdr *tcp_header = (struct udphdr *) (data + sizeof(struct iphdr));
                src_port = (unsigned int) ntohs(tcp_header->source);
                dest_port = (unsigned int) ntohs(tcp_header->dest);
            } else if (ip_header->protocol == ICMP) {


            }
            //printf("Transport layer ok. %d==%d %d==%d\n", src_port, current->source_port, dest_port,
            //       current->dest_port);
            if ((current->source_port > 0 && src_port != current->source_port) ||
                (current->dest_port > 0 && dest_port != current->dest_port)) {
                //prev->next = current->next;
                continue;
            }
            //printf("Now, I will decide %d\n", current->action);
            // If it comes to here, it means that it matches with the rule. So take the action in the rule.
            switch (current->action) {
                case ACCEPT:
                    nfq_set_verdict(q_handle, id, NF_ACCEPT, 0, NULL);
                    break;
                case REJECT:
                case DROP:
                    nfq_set_verdict(q_handle, id, NF_DROP, 0, NULL);
                    break;
                default:
                    nfq_set_verdict(q_handle, id, NF_ACCEPT, 0, NULL);
                    break;
            }
            // Verdict is set, return
            return 0;
        }

    }
    nfq_set_verdict(q_handle, id, NF_ACCEPT, 0, NULL);


}
/**
 * Handles L2 (DLL) layer rules.
 * @param nfa
 * @param data
 * @return
 */
int handle_l2(struct nfq_data *nfa, char **data) {

    int id = -1;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        //printf("hw_protocol=0x%04x hook=%u id=%u ",
        //       ntohs(ph->hw_protocol), ph->hook, id);
    } else {
        *data = NULL;
        return -1;
    }

    int ret = nfq_get_payload(nfa, data);
    if (ret < 0) {
        *data = NULL;
    }

    return id;

}
/**
 * Handle a packet with given data
 * @param nfa
 */
void packet_handler(struct nfq_data *nfa) {

    char *data = NULL;
    int id;
    //printf("Okay, will start handling new packet %p\n", nfa);
    if ((id = handle_l2(nfa, &data)) > -1) {
        if (!data) {
            //printf("Data is null........");
        } else {
            handle_l3l4(data, id);
        }
    }


}
/**
 * Each thread runs this function, which simply waits for a packet and then processes.
 * @param _ptr
 */
void thread_worker(void *_ptr) {
    while (1) {
        packet_queue_item_t *current = remove_packet_queue(packet_queue);
        packet_handler(current->data);
        free(current);
    }

}
/**
 * This is the callback set for NetFilter queue.
 * @param qh
 * @param nfmsg
 * @param nfa
 * @param data
 * @return
 */
int callback_pthread(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    if (qh != q_handle) {
        q_handle = qh;
    }
    add_packet_queue(packet_queue, nfa);

    return 0;
}
/**
 * Initializes pthread pool with given pool size and firewall rules.
 * @param pool_size
 * @param _packet_queue
 * @param _rules
 * @return
 */
int init_pthread_pool(int pool_size, packet_queue_t *_packet_queue, rule_t *_rules[]) {
    packet_queue = _packet_queue;
    rules = _rules;
    init_packet_queue(packet_queue);
    thread_pool = calloc(pool_size, sizeof(pthread_t));
    for (int i = 0; i < pool_size; ++i) {
        if (pthread_create(&thread_pool[i], NULL, thread_worker, NULL)) {
            perror("ERROR creating thread.");
        }
    }

}


