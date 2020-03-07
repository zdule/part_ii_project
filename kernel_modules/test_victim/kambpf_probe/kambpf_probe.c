#include <linux/kernel.h>   // printk
#include <linux/filter.h>   // bpf_prob
#include <linux/slab.h>     // kmalloc
#include <linux/bpf.h>

#include <kam/asm2bin.h>
#include "kambpf_probe.h"

int kamprobe_entry_handler_asm(void);

int kamprobe_entry_handler(struct kambpf_probe *kbp, struct pt_regs *regs) {
    u64 pseudo_stack[4];
    pseudo_stack[1] = kbp->ret_addr;
    pseudo_stack[0] = regs->bp;
    regs->sp = (unsigned long) &pseudo_stack[0];
    regs->bp = (unsigned long) &pseudo_stack[0]; // careful not to restore the wrong bp later
    regs->ip = kbp->call_dest;

    printk(KERN_INFO "Triggered : %px\n", kbp->bpf_prog);
    //return 0;
    return BPF_PROG_RUN(kbp->bpf_prog, regs);
}

/*
TODO: retprobes
noinline int probe_handler(void) {
KAM_PRE_ENTRY(tag_data);
    printk(KERN_INFO "Hello, tag: %px\n",*(tag_data));
KAM_PRE_RETURN(0);
}
*/

unsigned long callq_target(unsigned long addr) {
    return *((int *) (addr+1)) + 5 + addr;
}

struct kambpf_probe *kambpf_probe_alloc(unsigned long instruction_address, struct bpf_prog *bpf_prog) {
    struct kambpf_probe *kbp;
    int err = 0;

    if (!is_call_insn((u8 *)instruction_address)) {
        err = -EINVAL;
        goto err;
    }

    kbp = kmalloc(sizeof(struct kambpf_probe), GFP_KERNEL);
    if (!kbp) {
        err = -ENOMEM;
        goto err;
    }
    
    kbp->bpf_prog = bpf_prog_inc(bpf_prog);

    kbp->ret_addr = instruction_address + 5; 
    kbp->call_dest = callq_target(instruction_address);

    memset(&kbp->kp, 0, sizeof(kbp->kp));
    kbp->kp.addr_type = SUBSYS_PROBE_TYPE(0,ADDR_KERNEL,ADDR_OF_CALL);
    kbp->kp.on_entry = kamprobe_entry_handler_asm;
    kbp->kp.tag_data = (void *) kbp;
    kbp->kp.addr = (u8*) instruction_address;
    printk(KERN_INFO "Probbing with program %px\n",kbp->bpf_prog);

    err = kamprobe_register(&kbp->kp);
    printk(KERN_INFO ": kamprobe return val %d\n",err);
    if(err)
        goto err_bpf;

    return kbp;

err_bpf:
    bpf_prog_put(kbp->bpf_prog);
    kfree(kbp);
err:
    return ERR_PTR(err);
}

struct kambpf_probe *kambpf_probe_alloc_fd(unsigned long instruction_address, u32 bpf_prog_fd) {
	struct bpf_prog *prog = bpf_prog_get_type(bpf_prog_fd, BPF_PROG_TYPE_KPROBE); 
	struct kambpf_probe *probe;
    if (IS_ERR(prog)) {
        return ERR_PTR(PTR_ERR(prog));
    }
    
    probe = kambpf_probe_alloc(instruction_address, prog);
    bpf_prog_put(prog);
    return probe;
}

void kambpf_probe_free(struct kambpf_probe *kbp) {
    kamprobe_unregister(&kbp->kp);
    bpf_prog_put(kbp->bpf_prog);
    kfree(kbp);
}
