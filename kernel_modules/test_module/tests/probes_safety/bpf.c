/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map_def SEC("maps") triggered = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("kprobe/")
int prog(struct pt_regs *ctx)
{
    __u32 key = 0;
    __u32 val = 1;
    bpf_map_update_elem(&triggered, &key, &val, BPF_ANY);
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
