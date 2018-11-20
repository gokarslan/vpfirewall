//
// Created by Kerim Gökarslan on 11/19/18.
//

#ifndef VP_FIREWALL_PTHREAD_H
#define VP_FIREWALL_PTHREAD_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>


#include "vp_firewall_load.h"
#include "packet_queue.h"

int callback_pthread(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

int init_pthread_pool(int pool_size, packet_queue_t *packet_queue, rule_t *_rules[]);

#endif //VP_FIREWALL_PTHREAD_H
