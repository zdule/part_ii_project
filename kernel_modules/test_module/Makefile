#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

B ?= $(PWD)/build
S ?= $(PWD)

progs := 
objs :=
bpf_objects :=
deps :=
targets := 

include common.mk

test_helpers := $B/tests/test_helpers.o $B/tests/kallsyms.o
libkambpf := $B/libkambpf/libkambpf.o

$(eval $(call SUBMAKE,tests/probes_safety))
$(eval $(call SUBMAKE,libkambpf))

.DEFAULT_GOAL := all

.PHONY: all clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$B src=$(PWD) clean
	rm -rf $B/tests

userland := $B/tests/probes_correctness/entry_probe_userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf -lstdc++

userland := $B/tests/probes_correctness/return_probe_userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf -lstdc++

objs += $B/tests/test_helpers.o


bpf_objects += $B/tests/probes_correctness/bpf.o
bpf_objects += $B/tests/probes_correctness/return_bpf.o

$B/tests/kallsyms.o: $S/tests/kallsyms.cpp
	g++ -o $@ -c $<

$(objs): $B/%.o: $S/%.c
	gcc -o $@ -c $<

$(bpf_objects): $B/%.o: $S/%.c
	clang -I/usr/include/x86_64-linux-gnu -O2 -emit-llvm \
	 -c $< -o - | llc -march=bpf -filetype=obj -o $@

deps := $(objs:.o=.d)
#deps += $(bpf_objects:.o=.d)

$(deps): $B/%.d: $S/%.c 
	gcc -MM $< -MT '$(<:$S/%.c=$B/%.o) $@' -MF $@ 

.SECONDEXPANSION:
$(progs): %: $$($$@-objs) $$($$@-libs)
	gcc -o $@ $($@-objs) $($@-libs) $($@-lflags)

targets := $(objs)
targets += $(bpf_objects)
targets += $(progs) 
targets += $(deps)

.SECONDEXPANSION:
$(targets): %: | $$(@D)/.

$B/.:
	mkdir -p $@
$B/%/.:
	mkdir -p $@

all: $(targets) $B/Makefile $B/dummy_functions/.
	make -C /lib/modules/$(shell uname -r)/build M=$B src=$(PWD) modules

$B/Makefile:
	touch $@

include $(deps)
