BUILD_DIR ?= $(PWD)/build

.DEFAULT_GOAL := all

build/user_main: user_main.c
	gcc -I/usr/include -o build/user_main user_main.c -fsanitize=address -g
build/user_main.so: user_main.c
	gcc -shared -fPIC -o build/user_main.so user_main.c 
user_main_clean:
	rm build/user_main

build/Makefile: build
	touch $@

build:
	mkdir build

kamprobes_syms := /home/zdule/part_ii_project/kamprobes/build/Kbuild/Module.symvers

all: build/Makefile build/user_main build/user_main.so
	make -C /lib/modules/$(shell uname -r)/build KBUILD_EXTRA_SYMBOLS=$(kamprobes_syms) M=$(BUILD_DIR) src=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) clean
