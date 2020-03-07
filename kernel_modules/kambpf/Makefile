BUILD_DIR ?= $(PWD)/build

.DEFAULT_GOAL := all

build/Makefile: build
	touch $@

build:
	mkdir build

kamprobes_syms := $(KAMPROBES_SYMS) 

all: build/Makefile
	make -C /lib/modules/$(shell uname -r)/build KBUILD_EXTRA_SYMBOLS=$(kamprobes_syms) M=$(BUILD_DIR) src=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) clean
