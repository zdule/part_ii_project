BUILD_DIR ?= $(PWD)/build
SRC_DIR ?= $(PWD)

.PHONY: build_dir

all: $(BUILD_DIR)/bpf.o $(BUILD_DIR)/userland

build_dir:
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/bpf.o: $(SRC_DIR)/bpf.c build_dir
	clang -I/usr/include/x86_64-linux-gnu -O2 -emit-llvm \
	 -c $(SRC_DIR)/bpf.c -o - | llc -march=bpf -filetype=obj -o $@

$(BUILD_DIR)/userland: $(SRC_DIR)/userland.c build_dir
	gcc -o $@ $(SRC_DIR)/userland.c $(TEST_HELPERS) $(LIB_KAMBPF) -lbpf -lelf 

#$(BUILD_DIR)/asm.o: $(SRC_DIR)/asm.c
#	gcc -c $< -o $@
