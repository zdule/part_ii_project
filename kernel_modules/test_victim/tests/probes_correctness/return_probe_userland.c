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
#include "../kallsyms.h"
#include "../../ioctls.h"
#include "../../libkambpf/libkambpf.h"

struct perf_buf_cb_ctx {
    bool triggered;
    int stacks_fd;
};

const uint64_t arg1 = 0xDEADBEEFCAFFE077;
const uint64_t arg2 = 0xBDEFA1C035C221A4;
const uint64_t arg3 = 0x124;
const uint64_t arg4 = 0x1531;
const uint64_t arg5 = 0x14111;
const uint64_t arg6 = 0xABABA;
const uint64_t arg7 = 0xBAFAFA;
const uint64_t arg8 = 0x7;

void sample(void *ctx, int cpu, void *data, __u32 size) {
    struct perf_buf_cb_ctx *context = (struct perf_buf_cb_ctx *) ctx;
	struct return_probe_correctness_message *x = (struct return_probe_correctness_message *) data;
    passert(x->return_value == (arg1 ^ arg2 ^ arg3 ^ arg4 ^ arg5 ^ arg6 ^ arg7 ^ arg8),
			"Incorrect return value recorded %llx, expected %lx", x->return_value, arg1 ^ arg2 ^ arg3 ^ arg4 ^ arg5 ^ arg6 ^ arg7 ^ arg8);
    context->triggered = true;
    uint64_t stacks[10];
    bpf_map_lookup_elem(context->stacks_fd, &x->stack_id, stacks);
	char *str = lookup(stacks[0]);
	passert(strcmp(str,"EPC_traced_caller") == 0, "Expected first in stack to be EPC_traced_caller, found %s\n", str);
	free(str);
	/*
    for(int i = 0; i < 10; i++) {
		if (stacks[i] == 0) break;
		char *str = lookup(stacks[i]);
        printf("%lx %s\n",stacks[i], str);
		free(str);
	}
	*/
}

int main(int argc, char **argv) {
	init_kallsyms();
	struct bpf_object *obj = load_obj_or_exit(argv[1]);
	struct bpf_program *prog = find_program_by_name_or_exit(obj,"prog");
	int fd = bpf_program__fd(prog);
    int stacks_fd = find_map_fd_by_name_or_exit(obj, "stacks");

	//struct bpf_object *empty_obj = load_obj_or_exit(argv[2]);
    struct bpf_program *prog_empty = find_program_by_name_or_exit(obj, "empty");
    int empty_fd = bpf_program__fd(prog_empty);

    printf("FDS %d %d\n", fd, empty_fd);

    struct perf_buf_cb_ctx context = {
        .triggered = false,
        .stacks_fd = stacks_fd,
    };

	struct perf_buffer_opts opts = {
		.sample_cb = sample,
		.lost_cb = NULL,
		.ctx = &context,
	};

	struct perf_buffer *pb = setup_perf_events_cb(obj, "perf_event", 2, &opts);

    int ioctlfd = open("/dev/test_victim", O_RDONLY);
	passert(ioctlfd > 0, "Error opening testing device %s, ioctlfd=%d","/dev/test_victim",ioctlfd);

    uint64_t call_addr;

    int erry = ioctl(ioctlfd, IOCTL_GET_EPC , &call_addr);  
	passert(erry == 0, "Error retrieving address to probe, code=%d", erry);

	struct kambpf_updates_buffer *updates = kambpf_open_updates_device("/dev/kambpf_update", -1);
	int pos = kambpf_add_return_probe(updates, call_addr, empty_fd, fd);

    struct function_arguments args = {
        .arg1 = arg1,
        .arg2 = arg2,
        .arg3 = arg3,
        .arg4 = arg4,
        .arg5 = arg5,
        .arg6 = arg6,
        .arg7 = arg7,
        .arg8 = arg8,
    };

    int errx = ioctl(ioctlfd, IOCTL_RUN_EPC , &args);
	passert(errx == 0, "Error triggering the probed function, code=%d", errx);

	
	int cnt = perf_buffer__poll(pb, 200);
	passert(cnt == 1, "Number of events triggered not one cnt=%d", cnt);
    passert(context.triggered, "Event not registered");
	kambpf_remove_probe(updates, pos);

    errx = ioctl(ioctlfd, IOCTL_RUN_EPC , &args);
	passert(errx == 0, "Error triggering the probed function for the second time, code=%d", errx);
	cnt = perf_buffer__poll(pb, 50);
	passert(cnt == 0, "Probe should not trigger after it is deleted, cnt = %d\n", cnt);

    close(ioctlfd);
	perf_buffer__free(pb);
	bpf_object__unload(obj);

	printf("PASSED return_probe_correctness!\n");
	return 0;
}
