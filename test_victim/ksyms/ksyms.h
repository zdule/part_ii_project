/* SPDX-License-Identifier: GPL-2.0 */

// Copied from Linux Kernel /samples/bpf/bpf_load.h

struct ksym {
	long addr;
	char *name;
};

int load_kallsyms(void);
struct ksym *ksym_search(long key);
