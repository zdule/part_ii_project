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

void sample(void *ctx, int cpu, void *data, __u32 size) {
	struct entry_probe_correctness_message *x = (struct entry_probe_correctness_message *) data;
	passert(x->args.arg1 == 11001 && x->args.arg2 == 11002, 
			"Incorrect arguments recorded %lld %lld\n", x->args.arg1, x->args.arg2);
}

int main(int argc, char **argv) {
	struct bpf_object *obj = load_obj_or_exit(argv[1]);
	struct bpf_program *prog = find_program_by_name_or_exit(obj,"prog");
	int fd = bpf_program__fd(prog);
	
	struct perf_buffer_opts opts = {
		.sample_cb = sample,
		.lost_cb = NULL,
		.ctx = NULL,
	};

	struct perf_buffer *pb = setup_perf_events_cb(obj, "perf_event", 2, &opts);

    int ioctlfd = open("/dev/test_victim", O_RDONLY);
	passert(ioctlfd > 0, "Error opening testing device %s, ioctlfd=%d","/dev/test_victim",ioctlfd);

    uint64_t call_addr;

    int erry = ioctl(ioctlfd, IOCTL_GET_EPC , &call_addr);  
	passert(erry == 0, "Error retrieving address to probe, code=%d", erry);

	struct kambpf_updates_buffer *updates = kambpf_open_updates_device("/dev/kambpf_update", -1);
	kambpf_add_probe(updates, call_addr, fd);
    struct function_arguments args = {
        .arg1 = 11001,
        .arg2 = 11002,
    };

    int errx = ioctl(ioctlfd, IOCTL_RUN_EPC , &args);
	passert(errx == 0, "Error triggering the probed function, code=%d", errx);

    close(ioctlfd);
	
	int cnt = perf_buffer__poll(pb, 50);
	passert(cnt == 1, "Number of events triggered not one cnt=%d", cnt);

	perf_buffer__free(pb);
	bpf_object__unload(obj);
	return 0;
}
