BUILD_DIR ?= $(PWD)/build
SRC_DIR ?= $(PWD)

.PHONY: libkambpf

all: $(BUILD_DIR)/ksyms.o $(BUILD_DIR)/tests/entry_probe_correctness/bpf.o $(BUILD_DIR)/tests/entry_probe_correctness/userland
	mkdir -p $(BUILD_DIR)/kambpf_probe
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) clean
	SRC_DIR=$(SRC_DIR)/libkambpf OUT_DIR=$(BUILD_DIR)/libkambpf make -C libkambpf clean
	rm -rf $(BUILD_DIR)/tests

$(BUILD_DIR)/ksyms.o: ksyms/ksyms.c
	gcc -o $@ -c ksyms/ksyms.c

$(BUILD_DIR)/tests/entry_probe_correctness/userland: $(BUILD_DIR)/tests/test_helpers.o tests/entry_probe_correctness/userland.c libkambpf
	mkdir -p $(BUILD_DIR)/tests/entry_probe_correctness/
	gcc -o $@ tests/entry_probe_correctness/userland.c $(BUILD_DIR)/tests/test_helpers.o $(BUILD_DIR)/libkambpf/libkambpf.o -lbpf -lelf 

$(BUILD_DIR)/tests/test_helpers.o: tests/test_helpers.c
	mkdir -p $(BUILD_DIR)/tests/
	gcc -o $@ -c $< -lbpf -lelf

$(BUILD_DIR)/tests/entry_probe_correctness/bpf.o: tests/entry_probe_correctness/bpf.c
	mkdir -p build/tests/entry_probe_correctness
	clang -I/usr/include/x86_64-linux-gnu -O2 -emit-llvm \
	 -c $< -o - | llc -march=bpf -filetype=obj -o $@

libkambpf:
	SRC_DIR=$(SRC_DIR)/libkambpf OUT_DIR=$(BUILD_DIR)/libkambpf make -C libkambpf
