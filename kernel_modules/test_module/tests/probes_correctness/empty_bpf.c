/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

SEC("kprobe/empty")
int empty(struct pt_regs *ctx) {
    return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = LINUX_VERSION_CODE;
