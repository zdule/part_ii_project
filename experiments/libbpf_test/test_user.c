#include <stdio.h>
#include <stdlib.h>
#include <bpf/libbpf.h>
#include <unistd.h>

void sample(void *ctx, int cpu, void *data, __u32 size) {
	struct message {
		__u32 a;
		__u32 b;
	};
	struct message *x = (struct message *) data;
	printf("Message a = %d, b = %d\n",x->a, x->b);
}

int main(void) {
	struct bpf_object *obj = bpf_object__open("build/test_kern.o");
	if (!obj) {
		puts("Could not open object");
		return 1;
	}
	int ret = bpf_object__load(obj);
	if (ret) {
		puts("Could not load object");
		return -ret;
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,"prog");
	if (!prog) {
		puts("Could not select program from file");
		return -1;
	}

	int fd = bpf_program__fd(prog);
	printf("%d %d\n",ret, fd);
	
	struct perf_buffer_opts opts = {
		.sample_cb = sample,
		.lost_cb = NULL,
		.ctx = NULL,
	};
	int perf_event_array_fd = bpf_object__find_map_fd_by_name(obj,"perf_event");
	printf("Perf event array: %d\n",perf_event_array_fd);
	struct perf_buffer *pb = perf_buffer__new(perf_event_array_fd, 2, &opts);
	
	
	FILE *probe_file = fopen("/sys/module/simple_ebpf_run/parameters/probe", "w");
	fprintf(probe_file,"%d",fd);
	fclose(probe_file);
	perf_buffer__poll(pb, 1000);
	bpf_object__unload(obj);
	return 0;
}
