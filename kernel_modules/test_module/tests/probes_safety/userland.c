/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h> 
#include <assert.h>

#include "messages.h"
#include "../test_helpers.h"
#include "../../ioctls.h"
#include "../../libkambpf/libkambpf.h"

int main(int argc, char **argv) {
	struct bpf_object *obj = load_obj_or_exit(argv[1]);
	struct bpf_program *prog = find_program_by_name_or_exit(obj,"prog");
	int fd = bpf_program__fd(prog);
    int triggered_fd = find_map_fd_by_name_or_exit(obj, "triggered");

    int ioctlfd = open("/dev/test_module", O_RDONLY);
	passert(ioctlfd > 0, "Error opening testing device %s, ioctlfd=%d","/dev/test_module",ioctlfd);

    uint64_t call_addr;

    int erry = ioctl(ioctlfd, IOCTL_GET_EPS , &call_addr);  
	passert(erry == 0, "Error retrieving address to probe, code=%d", erry);
	
	struct kambpf_updates_buffer *updates = kambpf_open_updates_device("/dev/kambpf_update", -1);
	int pos = kambpf_add_probe(updates, call_addr, fd);

    control_block_t c;    
   /* 
    c[IN_ARGUMENT_REGISTER] = 11001;
    c[IN_TOP_OF_THE_STACK] = 11002;
    c[IN_CALLEE_SAVED_REGISTER] = 11003;
    c[IN_RETURN_VALUE] = 11004;
    */

    int errx = ioctl(ioctlfd, IOCTL_RUN_EPS, c);
	passert(errx == 0, "Error triggering the probed function, code=%d", errx);

    close(ioctlfd);

	kambpf_remove_probe(updates, pos);

    passert(c[CALLER_TOP_OF_STACK] == 54, "Caller top of stack\n");
    passert(c[CALLEE_TOP_OF_STACK] == 54, "Callee top of stack\n");
    passert(c[RETURN_VALUE_1] == 55, "return value 1\n");
    passert(c[RETURN_VALUE_2] == 56, "return value 2\n");
    for (int i = RBP; i <= R15; i++) {
        passert(c[i] == 44+i-RBP, "CALLEE saved argument garbled c[%d] == %d\n", i, c[i]);
    }
    for (int i = RSI; i <= R9; i++) {
        passert(c[i] == 49+i-RSI, "CALLEE saved argument garbled c[%d] == %d\n", i, c[i]);
    }
    passert(c[GRAND_OUT_RETURN_VALUE] == 242, "asm code in kernel failed... (not helpful :D)\n");

    /*
    passert(c[CALLEE_OUT_ARGUMENT_REGISTER] == 11001, "register garbled %llx\n", c[CALLEE_OUT_ARGUMENT_REGISTER]);
    passert(c[CALLEE_OUT_TOP_OF_THE_STACK] == 11002, "stack garbled %llx\n", c[CALLEE_OUT_TOP_OF_THE_STACK]);
    passert(c[CALLEE_OUT_CALLEE_SAVED_REGISTER] == 11003, "register garbled %llx\n", c[CALLEE_OUT_CALLEE_SAVED_REGISTER]);

    passert(c[CALLER_OUT_TOP_OF_THE_STACK] == 11002, "stack garbled %llx\n", c[CALLEE_OUT_TOP_OF_THE_STACK]);
    passert(c[CALLER_OUT_CALLEE_SAVED_REGISTER] == 11003, "register garbled %llx\n", c[CALLEE_OUT_CALLEE_SAVED_REGISTER]);
    passert(c[CALLER_OUT_RETURN_VALUE] == 11004, "return value garbled %llx\n", c[CALLER_OUT_RETURN_VALUE]);

    passert(c[CALLER_OUT_RETURN_VALUE] == 11004, "return value garbled %llx\n", c[CALLER_OUT_RETURN_VALUE]);
    */

    uint32_t key = 0, val;
    bpf_map_lookup_elem(triggered_fd, &key, &val);
    passert(val == 1, "Probe not triggered");
	bpf_object__unload(obj);
	
	printf("PASSED probes_safety!\n");
	return 0;
}
