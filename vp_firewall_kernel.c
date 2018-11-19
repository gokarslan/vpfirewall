#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>

#define ICMP 1
#define TCP 6
#define UDP 17

#define MODULE_NAME "vpFirewall"

MODULE_LICENSE("MIT");
MODULE_DESCRIPTION("vpFirewall");
MODULE_AUTHOR("Kerim Gokarslan");

/**
 * The handler for incoming traffic
 * initialized when the module is loaded.
 */
static struct nf_hook_ops nfho_in;
/** The handler for outgoing traffic
 *  initialized when the module is loaded.
 */
static struct nf_hook_ops nfho_out;


/**
 * Hook function for incoming packets, add all of them to queue
 * @param hooknum
 * @param skb
 * @param in
 * @param out
 * @param okfn
 * @return
 */
unsigned int fn_hook_incoming(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *)) {
    struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;
    struct list_head *p;
    struct mf_rule *a_rule;
    int i = 0;

    /*get src and dest ip addresses */

    unsigned int src_ip = (unsigned int) ip_header->saddr;
    unsigned int dest_ip = (unsigned int) ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    /* get src and dest port number */

    if (ip_header->protocol == UDP) {
        udp_header = (struct udphdr *) (skb_transport_header(skb));
        src_port = (unsigned int) ntohs(udp_header->source);
        dest_port = (unsigned int) ntohs(udp_header->dest);
    } else if (ip_header->protocol == TCP) {
        tcp_header = (struct tcphdr *) (skb_transport_header(skb));
        src_port = (unsigned int) ntohs(tcp_header->source);
        dest_port = (unsigned int) ntohs(tcp_header->dest);
    } else if (ip_header->protocol == ICMP) {
        icmp_header = (struct icmphdr *) (skb_transport_header(skb));
    } else {
        //return NF_ACCEPT;
    }
    /*if (dest_port != 22) {
        printk(KERN_INFO
        "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %un", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
    }
    if (dest_port == 8000) {
        printk(KERN_INFO
        "Added to queue");
        return NF_QUEUE;
    }*/
    // Accept SSH, testing purposes.
    if (dest_port == 22)
        return NF_ACCEPT;
    return NF_QUEUE;
}

/**
 * Hook function for outgoing traffic, add all of them to the queue.
 * @param hooknum
 * @param skb
 * @param in
 * @param out
 * @param okfn
 * @return
 */
unsigned int fn_hook_outgoing(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *)) {

    struct iphdr *ip_header = (struct iphdr *) skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;
    struct icmphdr *icmp_header;
    struct list_head *p;
    struct mf_rule *a_rule;

    int i = 0;

    /* get src and dest ip addresses */

    unsigned int src_ip = (unsigned int) ip_header->saddr;
    unsigned int dest_ip = (unsigned int) ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    /* get src and dest port number */

    if (ip_header->protocol == UDP) {
        udp_header = (struct udphdr *) (skb_transport_header(skb) + 20);
        src_port = (unsigned int) ntohs(udp_header->source);
        dest_port = (unsigned int) ntohs(udp_header->dest);

    } else if (ip_header->protocol == TCP) {
        tcp_header = (struct tcphdr *) (skb_transport_header(skb));
        src_port = (unsigned int) ntohs(tcp_header->source);
        dest_port = (unsigned int) ntohs(tcp_header->dest);
    } else if (ip_header->protocol == ICMP) {


    }
    /*if (src_port != 22) {
        printk(KERN_INFO
        "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %un", src_ip, src_port, dest_ip, dest_port, ip_header->protocol);
    }
    if (src_port == 8000) {
        printk(KERN_INFO
        "Added to queue/out");
        return NF_QUEUE;
    }*/
    if (src_port == 22)
        return NF_ACCEPT;
    return NF_QUEUE;
}

/**
 * Initialize the module, register for both incoming and outgoing traffic.
 * @return
 */
int init_module() {
    printk(KERN_INFO "Initialization of %s started", MODULE_NAME);
    /* Register the hook for incoming packets */

    nfho_in.hook = fn_hook_incoming;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_in);

    /* Register the hook for outgoing packets */

    nfho_out.hook = fn_hook_outgoing;
    nfho_out.hooknum = NF_INET_LOCAL_OUT;
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_out);    // Register the hook

    printk(KERN_INFO "%s initialized.", MODULE_NAME);
    return 0;
}

/**
 * When module is removed, unregister the incoming and outgoing traffic handlers
 */
void cleanup_module() {
    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);
    printk(KERN_INFO "kernel module unloaded.n");
}
