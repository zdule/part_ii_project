all: build/test_user build/test_kern.o

build/test_user: test_user.c
	gcc -Wall -fsanitize=address -o $@ $< -lbpf -lelf

build/test_kern.o: test_kern.c
	clang -I/usr/include/x86_64-linux-gnu -O2 -emit-llvm \
	 -c $< -o - | llc -march=bpf -filetype=obj -o $@
	 
clean:
	rm -rf build/test_user build/test_kern.o
