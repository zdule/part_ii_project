/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <linux/kernel.h>   // printk
#include <linux/filter.h>   // bpf_prob
#include <linux/slab.h>     // kmalloc
#include <linux/bpf.h>

#include <kam/asm2bin.h>
#include "kambpf_probe.h"

int kambpf_entry_handler_asm(void);
int kambpf_return_handler_asm(void);

u64 kambpf_entry_handler(struct kambpf_probe *kbp, struct pt_regs *regs) {
    int ret;
    regs->ip = kbp->call_addr;
	// compensate for pushing rsp after ss
	regs->sp += 8;

    preempt_disable();
    //rcu_read_lock(); // not needed ;)
    ret = BPF_PROG_RUN(kbp->bpf_entry_prog, regs); 
    //rcu_read_unlock();
    preempt_enable();

    return ret;
}

void kambpf_return_handler(struct kambpf_probe *kbp, struct pt_regs *regs) {
    regs->ip = kbp->call_addr;
    preempt_disable();
    regs->sp += 8;
    // No need to rcu_read_lock();!!!! We already hold the reference for the program.
    //rcu_read_lock();
    BPF_PROG_RUN(kbp->bpf_return_prog, regs); 
    //rcu_read_unlock();
    preempt_enable();
}

unsigned long callq_target(unsigned long addr) {
    return *((int *) (addr+1)) + 5 + addr;
}

void free_prog(struct bpf_prog **prog) {
    //printk(KERN_INFO"Putting bpf_prog %px\n", *prog);
    bpf_prog_put(*prog);
    //printk(KERN_INFO"DONE\n");
    *prog = NULL;
}

struct kambpf_probe *kambpf_probe_alloc_aux(unsigned long instruction_address, struct bpf_prog *bpf_entry_prog,
											struct bpf_prog *bpf_return_prog) {
    struct kambpf_probe *kbp;
    int err = 0;

    if (!is_call_insn((u8 *)instruction_address)) {
        printk(KERN_INFO"Not call instruction %lx", instruction_address);
        err = -EINVAL;
        goto err;
    }

    kbp = kmalloc(sizeof(struct kambpf_probe), GFP_KERNEL);
    if (!kbp) {
        err = -ENOMEM;
        goto err;
    }

    kbp->call_addr = instruction_address ; 
    kbp->bpf_entry_prog = kbp->bpf_return_prog = NULL;

    memset(&kbp->kp, 0, sizeof(kbp->kp));
    kbp->kp.addr_type = SUBSYS_PROBE_TYPE(0,ADDR_KERNEL,ADDR_OF_CALL);
	if (bpf_entry_prog) {
        kbp->bpf_entry_prog = bpf_prog_inc(bpf_entry_prog);
		kbp->kp.on_entry = kambpf_entry_handler_asm;
    }
	if (bpf_return_prog) {
        kbp->bpf_return_prog = bpf_prog_inc(bpf_return_prog);
		kbp->kp.on_return = kambpf_return_handler_asm;
    }
    kbp->kp.tag_data = (void *) kbp;
    kbp->kp.addr = (u8*) instruction_address;

    err = kamprobe_register(&kbp->kp);
    if(err) {
        printk(KERN_INFO"Kamprobe register error: %d\n",err);
        goto err_bpf;
    }

    return kbp;

err_bpf:
    if (kbp->bpf_entry_prog) {
        free_prog(&kbp->bpf_entry_prog);
    }
    if (kbp->bpf_return_prog) {
        free_prog(&kbp->bpf_return_prog);
    }
    kfree(kbp);
err:
    return ERR_PTR(err);
}

struct kambpf_probe *kambpf_probe_alloc(unsigned long instruction_address, u32 bpf_entry_prog_fd,
                                        u32 bpf_return_prog_fd) {
    struct bpf_prog *entry_prog, *return_prog;
    struct kambpf_probe *kbp;

    entry_prog = (bpf_entry_prog_fd != KAMBPF_PROBE_NOOP_FD) ?
                  bpf_prog_get_type(bpf_entry_prog_fd, BPF_PROG_TYPE_KPROBE) : (struct bpf_prog *) NULL;
    if (IS_ERR(entry_prog)) {
        kbp = ERR_PTR(PTR_ERR(entry_prog));
        entry_prog = NULL;
        goto err;
    }
    return_prog = (bpf_return_prog_fd != KAMBPF_PROBE_NOOP_FD) ?
                  bpf_prog_get_type(bpf_return_prog_fd, BPF_PROG_TYPE_KPROBE) : (struct bpf_prog *) NULL;
    if (IS_ERR(return_prog)) {
        kbp = ERR_PTR(PTR_ERR(return_prog));
        return_prog = NULL;
        goto err;
    }

    kbp = kambpf_probe_alloc_aux(instruction_address, entry_prog, return_prog);

    // Put programs because kambpf_probe_alloc_aux made its own copies
    if (entry_prog)
        bpf_prog_put(entry_prog);
    if (return_prog)
        bpf_prog_put(return_prog);

    //printk("Probe added %px %px\n", kbp->bpf_entry_prog, kbp->bpf_return_prog);
    return kbp;
err:
    if (entry_prog)
        free_prog(&entry_prog);
    if (return_prog)
        free_prog(&return_prog);
    return kbp;
}

void kambpf_probe_free(struct kambpf_probe *kbp) {
    kamprobe_unregister(&kbp->kp);
    if (kbp->bpf_entry_prog)
        free_prog(&kbp->bpf_entry_prog);
    if (kbp->bpf_return_prog)
        free_prog(&kbp->bpf_return_prog);
    kfree(kbp);
}
