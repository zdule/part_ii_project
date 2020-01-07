#ifndef KAMBPF_PROBE_H
#define KAMBPF_PROBE_H

#include <linux/filter.h>
#include <kam/probes.h>

struct kambpf_probe {
    kamprobe kp;
    struct bpf_prog *bpf_prog;
    unsigned long call_dest;
    unsigned long ret_addr;
};

struct kambpf_probe *kambpf_probe_alloc(unsigned long instruction_address, struct bpf_prog * prog);
struct kambpf_probe *kambpf_probe_alloc_fd(unsigned long instruction_address, u32 bpf_prog_fd);
void kambpf_probe_free(struct kambpf_probe *kbp);
#endif // KAMBPF_PROBE_H
