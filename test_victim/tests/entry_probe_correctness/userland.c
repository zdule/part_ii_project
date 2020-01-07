#include <bpf/libbpf.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h> 

#include "messages.h"
#include "../../ioctls.h"
void sample(void *ctx, int cpu, void *data, __u32 size) {
	struct entry_probe_correctness_message *x = (struct entry_probe_correctness_message *) data;
	printf("Message a = %lld, b = %lld\n",x->args.arg1, x->args.arg2);
}

int main(int argc, char **argv) {
	struct bpf_object *obj = bpf_object__open(argv[1]);
	if (!obj) {
		puts("Could not open object");
		exit(1);
	}
	int ret = bpf_object__load(obj);
	if (ret) {
		puts("Could not load object");
		exit(-ret);
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,"prog");
	if (!prog) {
		puts("Could not select program from file");
        exit(1);
	}

	int fd = bpf_program__fd(prog);
    printf("FD: %d\n",fd);
	
	struct perf_buffer_opts opts = {
		.sample_cb = sample,
		.lost_cb = NULL,
		.ctx = NULL,
	};

	int perf_event_array_fd = bpf_object__find_map_fd_by_name(obj,"perf_event");
	printf("Perf event array: %d\n",perf_event_array_fd);
	struct perf_buffer *pb = perf_buffer__new(perf_event_array_fd, 2, &opts);

    int ioctlfd = open("/dev/test_victim", O_RDONLY);
    if (!ioctlfd) {
        perror("Error ioctling the test victim");
        exit(1);
    }
    int erry = ioctl(ioctlfd, KAMBPF_SET_PROGRAM , FUNCTION_N_PROGRAM(0, fd));  
    if (erry) {
        printf("Error could not instrument function: %d\n",erry);
        exit(1);
    }
    struct function_arguments args = {
        .arg1 = 11001,
        .arg2 = 11002,
    };
    int errx = ioctl(ioctlfd,  KAMBPF_RUN_XOR10 , &args);
    if (errx) {
        printf("Error running instrumented function: %d\n",errx);
        exit(1);
    }
    close(ioctlfd);
	
	perf_buffer__poll(pb, 1000);
	bpf_object__unload(obj);
	return 0;
}
