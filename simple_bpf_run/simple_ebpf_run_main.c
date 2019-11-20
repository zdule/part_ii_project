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
    printk(KERN_INFO "Triggered : %px\n", prog);
    //return 0;
    return BPF_PROG_RUN(prog, regs);
}

noinline int probe_handler(void) {
KAM_PRE_ENTRY(tag_data);
    printk(KERN_INFO "Hello, tag: %px\n",*(tag_data));
KAM_PRE_RETURN(0);
}

noinline int probed_f(int x, char *str) {
    printk(KERN_INFO "PROBED FUNCTION %d %s\n",x, str);
    return 0;
}

// =========================================== Param bpf_prog ==============================================

void probed_caller(void);
void register_probe(u8 *addr, struct bpf_prog *prog);
struct bpf_prog *param_prog;

int set_param_prog(const char *val, const struct kernel_param *kp)
{
    struct bpf_prog ** param_prog = kp->arg;
    struct bpf_prog * prog = NULL;
    int fd = 0; 
    int err;

    if (*param_prog != NULL) {
        bpf_prog_put(*param_prog);
        *param_prog = NULL;
    }

    fd = 0;
    err = kstrtoint(val, 10, &fd);
    if (err) return err;
    printk(KERN_INFO "Received a bpf program file descriptor: %d\n", fd);
    
    prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_KPROBE); 
    if (IS_ERR(prog)) {
        return -EINVAL;
    }

    *param_prog = prog;
    printk(KERN_INFO "BPF program pointer set to %px\n", prog);
    return 0;
}

int set_param_call_addr(const char *val, const struct kernel_param *kp)
{
    unsigned long long addr = 0;
    u8 *add;
    int err;
    err = kstrtoull(val, 16, &addr);
    if (err) return err;
    add = (u8*) addr;
    printk(KERN_INFO "Received an address to instrument: %px\n", add);
    register_probe(add, param_prog);
    printk(KERN_INFO "Done registering a probe\n");
    return 0;
}

int set_param_trigger(const char *val, const struct kernel_param *kp) {
    probed_caller();
    return 0;
}

const struct kernel_param_ops param_ops_addr = 
{
    .set = &set_param_call_addr,  // Use our setter ...
    .get = NULL,     // .. and standard getter
};

long long no_parameter = 0;
module_param_cb(addr, /*filename*/
    &param_ops_addr,
    &no_parameter, /* pointer to variable, contained parameter's value */
    S_IWUSR /*permissions on file*/
);

const struct kernel_param_ops param_ops_prog = 
{
    .set = &set_param_prog,  // Use our setter ...
    .get = NULL,     // .. and standard getter
};

struct bpf_prog *param_prog = NULL;
module_param_cb(prog, /*filename*/
    &param_ops_prog, /*operations*/
    &param_prog, /* pointer to variable, contained parameter's value */
    S_IWUSR /*permissions on file*/
);

char test_address_buffer[20];
char *test_address = test_address_buffer;
module_param(test_address, charp, S_IRUSR);

const struct kernel_param_ops param_ops_trigger = {
    .set = set_param_trigger,
    .get = NULL,
};

module_param_cb(trigger,
    &param_ops_trigger,
    NULL,
    S_IWUSR
);

void init_test_address_string(void) {
    u8 *probed_instruction = (u8*) probed_caller + 21;
    snprintf(test_address_buffer, sizeof(test_address_buffer), "%lx", (unsigned long) probed_instruction);
}

// ===========================================================================================================

noinline void probed_caller(void) {
    probed_f(42,"Hello world");
}

void register_probe(u8 *addr, struct bpf_prog *prog) {
    kamprobe kamp;
    
    memset(&kamp, 0, sizeof(kamp));
    kamp.addr_type = SUBSYS_PROBE_TYPE(0,ADDR_KERNEL,ADDR_OF_CALL);
    kamp.on_entry = kamprobe_entry_handler_asm;
    prog = bpf_prog_inc(prog);
    printk(KERN_INFO "Probbing with program %px\n",prog);
    kamp.tag_data = (void *) prog;
    kamp.addr = addr;

    kamprobe_register(&kamp);
}
// ===========================================================================================================
static int __init simple_ebpf_run_init(void) {
    kamprobes_init(200);
    init_test_address_string();
    printk(KERN_INFO "simple_ebpf_run loaded\n");
    return 0;
}

static void __exit simple_ebpf_run_exit(void) {
    printk(KERN_INFO "simple_ebpf_run unloaded\n");
}

module_init(simple_ebpf_run_init);
module_exit(simple_ebpf_run_exit);
