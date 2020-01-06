/* Copyright (c) 2013-2015 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <asm/ptrace.h>
#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
	.map_flags = 0,
};

struct bpf_map_def SEC("maps") perf_event = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(__u32),
	.max_entries = 16,
};

SEC("kprobe/sys_mkdir")
int prog(struct pt_regs *ctx)
{
	char fmt[] = "Run bpf %s";
	char *s;
	
	__u32 id = 0;
	__u32 *v = bpf_map_lookup_elem(&my_map, &id);
	if (v)
	*v = 1;
	
	struct {
		__u32 a;
		__u32 b;
	} message = {
		.a = 1,
		.b = 2,
	};
	
	__u32 cpuid = bpf_get_smp_processor_id();
	bpf_perf_event_output(ctx, &perf_event, cpuid, &message, sizeof(message));
	
	s = (char *) PT_REGS_PARM1(ctx);
	bpf_trace_printk(fmt, sizeof(fmt), s);
	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
