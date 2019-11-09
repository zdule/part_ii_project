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

/* Assumes a "tag" pointer is stored in ESP-8.
   Constructs a pt_regs struct on the stack, bellow the tag pointer.
*/

int naked asm_handler(void) {
    // Load the "tag" pointer from rsp-8 to r11
    asm("mov -8(rsp), r11"); 

    // Since the stack is growing downwards, the pt_regs structure
    // is filled from the back to the front  

    // skip ss, rsp, flags, cs, rip, orig_rax  = 6 registers
    // I dont have a use for these at the moment
    asm("sub 48, rsp");

    // Save argument carrying registers to pass them to the eBPF program
    // But also to restore them at the end of the function
    asm("push rdi");
    asm("push rsi");
    asm("push rdx");
    asm("push rcx");
    asm("push rax");
    asm("push r8");
    asm("push r9");
    asm("push r10");
    
    // Skip r11, and rbx = 2 registers
    // these don't hold  arguments don't need to be restored
    asm("sub 16, rsp");

    // Save rbp to pass it to eBPF
    asm("push rbp");

    // Skip r12, r13, r14, r15 = 4 registers
    // these dont hold arguments and dont need to be restored
    asm("sub 32, rsp");

    // Now rsp points to the pt_regs structure on the stack
    // From now on I can clobber all the callee-clobbered registers

    // r11 points to the bpf_prog struct which should be executed

    // We now want to make the function call:
    // (r11->bpf_func)(rsp, r11->isnsi);    

    // Load the bpf function from the struct
    asm("mov offFunc(r11), r10");
    // Load the first argument (pt_regs* from rsp) to rdi
    asm("mov rsp, rdi");
    // Load the second argument, the non-JITed ebpf instructions 
    // from the struct, and store them in rsi
    asm("mov offISNSI(r11), rsi");
    
    // We finally make the function call
    asm("call r10");
    
    // We now need to restore the function argument registers
    
    // Pop r15, r14, r13, r12, rbp, rbx, r11 = 7 registers
    asm("add 56, rsp");

    // Restore the argument registers
    asm("pop r10");
    asm("pop r9");
    asm("pop r8");
    asm("pop rax");
    asm("pop rcx");
    asm("pop rdx");
    asm("pop rsi");
    asm("pop rdi");

    // Pop orig_rax, rip, cs, flags, rsp, cs = 6 register
    asm("add 48, rsp");

    asm("ret");
}

noinline int probe_handler(void) {
KAM_PRE_ENTRY(tag_var);
    long long abcd = 0;
    long long x2 = 0;
    long long x3 = 0;
    long long x4 = 0;
    long long x5 = 0;
    long long x6 = 0;
    long long x7 = 0;
    long long x8 = 0;
    volatile long x9 = 0;
    asm __volatile__(""::"m"(abcd), "m" (x2), "m" (x3), "m" (x4), "m" (x5), "m" (x6), "m" (x7), "m" (x8), "m" (x9));
    printk(KERN_INFO "%px %px %px %px\n",__rscfl_reserved_rbp,__rscfl_reserved_stack,&tag_var,&abcd);
    printk(KERN_INFO "Hello, tag: %d %lld\n",*(tag_var+2),abcd);
KAM_PRE_RETURN(0);
}

noinline int probed_f(void) {
    printk(KERN_INFO "PROBED\n");
    return 0;
}

// =========================================== Param bpf_prog ==============================================

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
    kamp.tag = 12345678;
    //kamp.on_return = probe_handler;
    kamp.addr = add;

    kamprobe_register(&kamp);
    printk(KERN_INFO "Done registering a probe\n");
    return 0;
}

int get_param_prog(char *buff, const struct kernel_param *kp) {
label:
    probed_f();
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

static int __init simple_ebpf_run_init(void) {
    kamprobes_init(200);
    printk(KERN_INFO "simple_ebpf_run loaded\n");
    return 0;
}

static void __exit simple_ebpf_run_exit(void) {
    printk(KERN_INFO "simple_ebpf_run unloaded\n");
}

module_init(simple_ebpf_run_init);
module_exit(simple_ebpf_run_exit);
