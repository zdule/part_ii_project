obj-m += simple_ebpf_run.o
ccflags-y := -I/usr/local/include

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
