#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/filter.h>
#include <linux/string.h>

#include <linux/bpf.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Module that runs an ebpf program.");
MODULE_VERSION("0.01");

#include <kam/probes.h>
#include "kambpf_probe.h"

noinline int probed_f(int x, char *str) {
    printk(KERN_INFO "PROBED FUNCTION %d %s\n",x, str);
    return 0;
}

noinline void probed_caller(void) {
    probed_f(42,"Hello world");
}

// =========================================== Param bpf_prog ==============================================

struct kambpf_probe *probe;

int set_param_probe(const char *fd_str, const struct kernel_param *kp) {
    int fd = 0; 
    unsigned long long addr = 0;
    int err;

    err = kstrtoint(fd_str, 10, &fd);
    if (err) {
    	printk(KERN_INFO "Invalid fd format: %s\n", fd_str);
    	return err;
    }
    
    addr = ((unsigned long long)probed_caller)+21;
    
    printk(KERN_INFO "Received a bpf program file descriptor: %d\n", fd);
    printk(KERN_INFO "Calculated the address to instrument: %llx\n", addr);
    
    if (probe != NULL) {
    	kambpf_probe_free(probe);
    }
    probe = kambpf_probe_alloc_fd(addr, fd);
    
    if (IS_ERR(probe)) {
    	err = PTR_ERR(probe);
    	probe = NULL;
    	return err;
    }
    
    probed_caller();
    return 0;
}

const struct kernel_param_ops param_ops_probe = 
{
    .set = &set_param_probe,  // Use our setter ...
    .get = NULL,     // .. and standard getter
};

struct bpf_prog *param_probe = NULL;
module_param_cb(probe, /*filename*/
    &param_ops_probe, /*operations*/
    &probe, /* pointer to variable, contained parameter's value */
    S_IWUSR /*permissions on file*/
);

// ======================================= Param trigger ====================================================

int set_param_trigger(const char *val, const struct kernel_param *kp) {
    probed_caller();
    return 0;
}

const struct kernel_param_ops param_ops_trigger = {
    .set = set_param_trigger,
    .get = NULL,
};

module_param_cb(trigger,
    &param_ops_trigger,
    NULL,
    S_IWUSR
);

// ==================================== Param test_address =================================================

char test_address_buffer[20];
char *test_address = test_address_buffer;
module_param(test_address, charp, S_IRUSR);

void init_test_address_string(void) {
    u8 *probed_instruction = (u8*) probed_caller + 21;
    snprintf(test_address_buffer, sizeof(test_address_buffer), "%lx", (unsigned long) probed_instruction);
}

// ===========================================================================================================

static int __init simple_ebpf_run_init(void) {
    kamprobes_init(200);
    init_test_address_string();
    printk(KERN_INFO "simple_ebpf_run loaded\n");
    return 0;
}

static void __exit simple_ebpf_run_exit(void) {
    if (probe != NULL) {
    	kambpf_probe_free(probe);
    	probe = NULL;
    }
    
    printk(KERN_INFO "simple_ebpf_run unloaded\n");
}

module_init(simple_ebpf_run_init);
module_exit(simple_ebpf_run_exit);
