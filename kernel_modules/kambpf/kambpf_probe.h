#ifndef KAMBPF_PROBE_H
#define KAMBPF_PROBE_H

#include <linux/filter.h>
#include <kam/probes.h>

struct kambpf_probe {
    kamprobe kp;
    struct bpf_prog *bpf_entry_prog;
    struct bpf_prog *bpf_return_prog;
    unsigned long call_addr;
};

#define KAMBPF_PROBE_NOOP_FD -1

struct kambpf_probe *kambpf_probe_alloc(unsigned long instruction_address, u32 bpf_entry_prog_fd,
										u32 bpf_return_prog_fd);
void kambpf_probe_free(struct kambpf_probe *kbp);
#endif // KAMBPF_PROBE_H
