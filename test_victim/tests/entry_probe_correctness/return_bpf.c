#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "messages.h"

struct bpf_map_def SEC("maps") perf_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

struct bpf_map_def SEC("maps") stacks = {
	.type = BPF_MAP_TYPE_STACK_TRACE,
	.key_size = sizeof(__u32),
	.value_size = 10*sizeof(__u64),
	.max_entries = 2,
};

SEC("kprobe/prog")
int prog(struct pt_regs *ctx)
{
    struct return_probe_correctness_message message;
    message.return_value = ctx->rax;

    message.stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);

    bpf_perf_event_output(ctx, &perf_event, BPF_F_CURRENT_CPU, &message, sizeof(message));
	
	return 0;
}

SEC("kprobe/empty")
int empty(struct pt_regs *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
