obj-m += vp_firewall_kernel.o

FLAGS=-std=c99
LIBS=-lnetfilter_queue -lpthread
all: vp_firewall vp_firewall_kernel

vp_firewall: vp_firewall_load.c vp_firewall_pthread.c packet_queue
	gcc $(FLAGS) packet_queue.o vp_firewall_load.c vp_firewall_pthread.c vp_firewall.c -o vp-firewall $(LIBS)
packet_queue:
	gcc $(FLAGS) -c packet_queue.c
#vp_firewall_pthread:
#	gcc $(FLAGS) -c vp_firewall_pthread.c
#vp_firewall_load:
#	gcc $(FLAGS) -c vp_firewall_load.c

vp_firewall_kernel:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
