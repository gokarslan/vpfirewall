//
// Created by Kerim Gökarslan on 11/19/18.
//

#ifndef VPFIREWALL_PACKET_QUEUE_H
#define VPFIREWALL_PACKET_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct packet_queue_item {
    struct nfq_data *data;
    struct packet_queue_item *next;

} packet_queue_item_t;

typedef struct packet_queue {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct packet_queue_item *item;
    int size;

} packet_queue_t;

void init_packet_queue(packet_queue_t *queue);
int is_packet_queue_empty(packet_queue_t *queue);
void add_packet_queue(packet_queue_t *queue, struct nfq_data *data);
packet_queue_item_t* remove_packet_queue(packet_queue_t *queue);

#endif //VPFIREWALL_PACKET_QUEUE_H
