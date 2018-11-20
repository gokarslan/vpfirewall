//
// Created by Kerim Gökarslan on 11/19/18.
//

#include "packet_queue.h"


int is_queue_empty(packet_queue_t *queue) {
    return queue->size == 0;

}

void add_packet_queue(packet_queue_t *queue, struct nfq_data *data) {
    pthread_mutex_lock(&queue->mutex);
    packet_queue_item_t *current = calloc(1, sizeof(packet_queue_t));
    current->data = data;
    current->next = queue->item;
    queue->item = current;
    queue->size ++;
    pthread_mutex_unlock(&queue->mutex);
    pthread_cond_signal(&queue->cond);

}

packet_queue_item_t *remove_packet_queue(packet_queue_t *queue) {

    pthread_mutex_lock(&queue->mutex);
    while (is_queue_empty(queue))
        pthread_cond_wait(&queue->cond, &queue->mutex);
    packet_queue_item_t *current = queue->item;
    queue->item = queue->item->next;
    queue->size --;
    pthread_mutex_unlock(&queue->mutex);
    return current;

}

void init_packet_queue(packet_queue_t *queue) {
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
    queue->size = 0;
    queue->item = NULL;
}