#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "vp_firewall_load.h"
#include "vp_firewall_pthread.h"
#include "packet_queue.h"

static rule_t *rules[CHAIN_SIZE] = {NULL, NULL, NULL};

// compile with -lnetfilter_queue
// install quque_devel


int main(int argc, char **argv) {
    printf("vpFirewall is starting...\n");
    char *config_path = "vp_firewall.conf";
    if (load_rules(rules, config_path) == 0) {
        printf("Rules are loaded from %s\n", config_path);
    } else {
        printf("Rules cannot be loaded from %s\n", config_path);
        return -1;
    }
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    int pool_size = 12;
    packet_queue_t *packet_queue = calloc(1, sizeof(packet_queue_t));
    init_pthread_pool(pool_size, packet_queue, rules);

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h, 0, &callback_pthread, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    printf("vpFirewall started.\n");
    while ((rv = recv(fd, buf, sizeof(buf), 0))) {
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);


    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}