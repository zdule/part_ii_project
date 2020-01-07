BUILD_DIR ?= $(PWD)/build


all: $(BUILD_DIR)/ksyms.o $(BUILD_DIR)/tests/entry_probe_correctness/bpf.o $(BUILD_DIR)/tests/entry_probe_correctness/userland
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(BUILD_DIR) src=$(PWD) clean
	rm $(BUILD_DIR)/ksyms.o

$(BUILD_DIR)/ksyms.o: ksyms/ksyms.c
	gcc -o $@ -c ksyms/ksyms.c

$(BUILD_DIR)/tests/entry_probe_correctness/userland: tests/entry_probe_correctness/userland.c
	gcc -o $@ $< -lbpf -lelf 

$(BUILD_DIR)/tests/entry_probe_correctness/bpf.o: tests/entry_probe_correctness/bpf.c
	mkdir -p build/tests/entry_probe_correctness
	clang -I/usr/include/x86_64-linux-gnu -O2 -emit-llvm \
	 -c $< -o - | llc -march=bpf -filetype=obj -o $@
