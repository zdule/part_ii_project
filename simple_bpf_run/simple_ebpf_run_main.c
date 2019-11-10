#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/filter.h>

#include <linux/bpf.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Module that runs an ebpf program.");
MODULE_VERSION("0.01");

#include <kam/probes.h>

int kamprobe_entry_handler_asm(void);

int kamprobe_entry_handler(struct bpf_prog *prog, struct pt_regs *regs) {
    return BPF_PROG_RUN(prog, regs);
}

noinline int probe_handler(void) {
KAM_PRE_ENTRY(tag_data);
    printk(KERN_INFO "Hello, tag: %px\n",*(tag_data));
KAM_PRE_RETURN(0);
}

noinline int probed_f(void) {
    printk(KERN_INFO "PROBED\n");
    return 0;
}

// =========================================== Param bpf_prog ==============================================

void probed_caller(void);

int set_param_prog(const char *val, const struct kernel_param *kp)
{
    struct bpf_prog ** arg = kp->arg;
    struct bpf_prog * prog = NULL;
    struct pt_regs regs;
    int fd = 0; 
    int err;
    memset(&regs, 0, sizeof(struct pt_regs));

    fd = 0;
    err = kstrtoint(val, 10, &fd);
    if (err) return err;
    printk(KERN_INFO "Received a bpf program file descriptor: %d\n", fd);
    
    prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_KPROBE); 
    if (IS_ERR(prog)) {
        return -EINVAL;
    }
    BPF_PROG_RUN(prog, &regs);
    BPF_PROG_RUN(prog, &regs);
    BPF_PROG_RUN(prog, &regs);

    *arg = prog;
    printk(KERN_INFO "BPF program pointer set to %p\n", prog);
    return 0;
}

int set_param_call_addr(const char *val, const struct kernel_param *kp)
{
    unsigned long long addr = 0;
    u8 *add;
    int err;
    kamprobe kamp;
    err = kstrtoull(val, 16, &addr);
    if (err) return err;
    add = (u8*) addr;
    printk(KERN_INFO "Received an address to instrument: %px\n", add);
    
    memset(&kamp, 0, sizeof(kamp));
    kamp.addr_type = SUBSYS_PROBE_TYPE(0,ADDR_KERNEL,ADDR_OF_CALL);
    kamp.on_entry = probe_handler;
    kamp.tag_data = (void *) 0xdeadbeefcaffe123;
    //kamp.on_return = probe_handler;
    kamp.addr = add;

    kamprobe_register(&kamp);
    printk(KERN_INFO "Done registering a probe\n");
    return 0;
}


int get_param_prog(char *buff, const struct kernel_param *kp) {
label:
    probed_f();
    probed_caller();
    printk(KERN_INFO "simple_ebpf_run %px\n",&&label);
    strcpy(buff,"-1");
    return 2;
}

const struct kernel_param_ops param_ops_addr = 
{
    .set = &set_param_call_addr,  // Use our setter ...
    .get = &get_param_prog,     // .. and standard getter
};

long long param_addr = 0;
module_param_cb(addr, /*filename*/
    &param_ops_addr,
    &param_addr, /* pointer to variable, contained parameter's value */
    S_IRUGO | S_IWUSR /*permissions on file*/
);

const struct kernel_param_ops param_ops_prog = 
{
    .set = &set_param_prog,  // Use our setter ...
    .get = &get_param_prog,     // .. and standard getter
};

struct bpf_prog *param_prog = NULL;
module_param_cb(prog, /*filename*/
    &param_ops_prog, /*operations*/
    &param_prog, /* pointer to variable, contained parameter's value */
    S_IRUGO | S_IWUSR /*permissions on file*/
);

// ===========================================================================================================

void probed_caller(void) {
    probed_f();
}

void register_probe(void) {
    kamprobe kamp;
    char * addr = (char *)&probed_caller;
    addr += 9;
    printk(KERN_INFO "Received an address to instrument: %px\n", addr);
    
    memset(&kamp, 0, sizeof(kamp));
    kamp.addr_type = SUBSYS_PROBE_TYPE(0,ADDR_KERNEL,ADDR_OF_CALL);
    kamp.on_entry = probe_handler;
    kamp.tag_data = (void *) 0xdeadbeefcaffe123;
    //kamp.on_return = probe_handler;
    kamp.addr = addr;

    kamprobe_register(&kamp);
    printk(KERN_INFO "Done registering a probe\n");
}
// ===========================================================================================================
static int __init simple_ebpf_run_init(void) {
    kamprobes_init(200);
    register_probe();
    probed_caller();
    printk(KERN_INFO "simple_ebpf_run loaded\n");
    return 0;
}

static void __exit simple_ebpf_run_exit(void) {
    printk(KERN_INFO "simple_ebpf_run unloaded\n");
}

module_init(simple_ebpf_run_init);
module_exit(simple_ebpf_run_exit);
