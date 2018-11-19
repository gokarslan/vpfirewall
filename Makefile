obj-m += vp_firewall_kernel.o

all: vp_firewall vp_firewall_kernel

vp_firewall:
	gcc vp_firewall.c -o vp-firewall -lnetfilter_queue

vp_firewall_load:
	gcc -c vp_firewall_load.c

vp_firewall_kernel:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
