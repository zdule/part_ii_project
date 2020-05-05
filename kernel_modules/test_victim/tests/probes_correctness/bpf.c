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

SEC("kprobe/")
int prog(struct pt_regs *ctx)
{
    struct entry_probe_correctness_message message = {
        .args = {
            .arg1 = PT_REGS_PARM1(ctx),
            .arg2 = PT_REGS_PARM2(ctx),
            .arg3 = PT_REGS_PARM3(ctx),
            .arg4 = PT_REGS_PARM4(ctx),
            .arg5 = PT_REGS_PARM5(ctx),
            .arg6 = 0L,
            .arg7 = 0L,
            .arg8 = 0L,
        },
        .stack_id = 0,
    };
    
	//bpf_probe_read_kernel(&message.args.arg7, sizeof(message.args.arg7), (void *) ctx->rsp);
    //bpf_probe_read_kernel(&message.args.arg8, sizeof(message.args.arg8), (void *) ctx->rsp+8);

    message.stack_id = bpf_get_stackid(ctx, &stacks, BPF_F_FAST_STACK_CMP | BPF_F_REUSE_STACKID);

    bpf_perf_event_output(ctx, &perf_event, BPF_F_CURRENT_CPU, &message, sizeof(message));
	
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
