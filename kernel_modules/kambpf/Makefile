#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

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
