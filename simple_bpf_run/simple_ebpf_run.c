#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/filter.h>

#include <linux/bpf.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Module that runs an ebpf program.");
MODULE_VERSION("0.01");

// =========================================== Param bpf_prog ==============================================

int set_param_prog(const char *val, const struct kernel_param *kp)
{
    struct bpf_prog ** arg = kp->arg;
    struct bpf_prog * prog;
    struct pt_regs regs;
    memset(&regs, 0, sizeof(struct pt_regs));

    int fd = 0; 
    int err = kstrtoint(val, 10, &fd);
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

int get_param_prog(char *buff, const struct kernel_param *kp) {
    strcpy(buff,"-1");
    return 2;
}

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

static int __init simple_ebpf_run_init(void) {
    printk(KERN_INFO "simple_ebpf_run loaded\n");
    return 0;
}

static void __exit simple_ebpf_run_exit(void) {
    printk(KERN_INFO "simple_ebpf_run unloaded\n");
}

module_init(simple_ebpf_run_init);
module_exit(simple_ebpf_run_exit);
