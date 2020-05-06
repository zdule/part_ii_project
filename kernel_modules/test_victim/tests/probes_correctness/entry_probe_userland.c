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

void sample(void *ctx, int cpu, void *data, __u32 size) {
    struct perf_buf_cb_ctx *context = (struct perf_buf_cb_ctx *) ctx;
	struct entry_probe_correctness_message *x = (struct entry_probe_correctness_message *) data;
	passert(x->args.arg1 == 11001 && x->args.arg2 == 11002 && x->args.arg3 == 11003 && x->args.arg4 == 11004 && x->args.arg5 == 11005 && x->args.arg6 == 11006
			&& x->args.arg7 == 11007 && x->args.arg8 == 11008, 
			"Incorrect arguments recorded %lld %lld %lld %lld %lld %lld %lld %lld\n", x->args.arg1, x->args.arg2, x->args.arg3, x->args.arg4, x->args.arg5,
			x->args.arg6, x->args.arg7, x->args.arg8);
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
	int pos = kambpf_add_probe(updates, call_addr, fd);
    passert(pos > 0, "Error instrumenting probe, code = %d\n",pos);
    struct function_arguments args = {
        .arg1 = 11001,
        .arg2 = 11002,
        .arg3 = 11003,
        .arg4 = 11004,
        .arg5 = 11005,
        .arg6 = 11006,
        .arg7 = 11007,
        .arg8 = 11008,
    };

    int errx = ioctl(ioctlfd, IOCTL_RUN_EPC , &args);
	passert(errx == 0, "Error triggering the probed function, code=%d", errx);
	
	int cnt = perf_buffer__poll(pb, 50);
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

	printf("PASSED entry_probe_correctness!\n");
	return 0;
}
