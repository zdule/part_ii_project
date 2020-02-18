B ?= $(PWD)/build
S ?= $(PWD)

progs := 
objs :=
bpf_objects :=
deps :=
targets := 

include common.mk

test_helpers := $B/tests/test_helpers.o
libkambpf := $B/libkambpf/libkambpf.o

$(eval $(call SUBMAKE,tests/entry_probe_safety))
$(eval $(call SUBMAKE,libkambpf))

.DEFAULT_GOAL := all

.PHONY: all clean

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$B src=$(PWD) clean
	rm -rf $B/tests

objs += $B/ksyms/ksyms.o

userland := $B/tests/entry_probe_correctness/userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf

userland := $B/tests/entry_probe_correctness/return_probe_userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf

objs += $B/tests/test_helpers.o


bpf_objects += $B/tests/entry_probe_correctness/bpf.o
bpf_objects += $B/tests/entry_probe_correctness/return_bpf.o

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

all: $(targets) $B/Makefile
	make -C /lib/modules/$(shell uname -r)/build M=$B src=$(PWD) modules

$B/Makefile:
	touch $@

include $(deps)
