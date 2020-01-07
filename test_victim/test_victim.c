#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>	// dev_t macros
#include <linux/fs.h>		// registering devices, file operations
#include <linux/cdev.h>	
#include <linux/slab.h>		// kmalloc
#include <linux/errno.h>

#include <asm/uaccess.h>    // put_user

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Test module to probe");
MODULE_VERSION("0.01");

#define MODULE_NAME "test_victim"

uint major = 0;
module_param(major, uint, S_IRUGO);

struct cdev cdev;

int open(struct inode *inode, struct file *filp) {
	return 0;
}

int release(struct inode *inode, struct file *filp) {
	return 0;
}

noinline long traced_function(unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO "Traced function: %u %lu\n", cmd, arg);
    return cmd;
}

noinline long traced_caller(unsigned int cmd, unsigned long arg) {
    return traced_function(cmd, arg);
}

#include "ioctls.h"
#include "tests/entry_probe_correctness/kernel.h"
#include <linux/uaccess.h>

#include "kambpf_probe/kambpf_probe.h"

unsigned long long call_addresses[] = {
    EPC_call_address,
};
struct kambpf_probe *probes[] = {
    NULL,
};

long test_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO"recieved ioctl\n");
    if (cmd == KAMBPF_SET_PROGRAM) {
        u32 fd = GET_PROGRAM(arg);
        u32 fun_id = GET_FUNCTION(arg);
        if (probes[fun_id] != NULL) {
            kambpf_probe_free(probes[fun_id]);
            probes[fun_id] = NULL;
        }
        printk(KERN_INFO"fd: %d\n",fd);

        if (fd == -1)
            return 0;
        probes[fun_id] = kambpf_probe_alloc_fd(call_addresses[fun_id], fd);
        printk(KERN_INFO"set probe\n");
        if (IS_ERR(probes[fun_id])) {
            probes[fun_id] = NULL;
            return PTR_ERR(probes[fun_id]);
        }
        return 0;
    }
    else if (cmd == KAMBPF_RUN_XOR10) {
        struct function_arguments args;
        if (copy_from_user(&args, (void *)arg, sizeof(struct function_arguments)) != 0)
            return -EINVAL;
        EPC_traced_caller(&args);
        return 0;
    } else return -EINVAL;
    return traced_caller(cmd, arg);
}

struct file_operations f_ops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = test_ioctl,
	.open = open,
	.release = release,
};

int register_major_num(void) {
    int err = 0;
    if (major)
        err = register_chrdev_region(MKDEV(major,0), 1, MODULE_NAME);
    else {
        dev_t dev;
        err = alloc_chrdev_region(&dev, 0, 1, MODULE_NAME);
        if (!err)
            major = MAJOR(dev); 
    }
    return err;
}

void unregister_major_num(void) {
    unregister_chrdev_region(MKDEV(major, 0), 1);
}

static int __init test_victim_init(void) {
	int err;
    err = register_major_num();
	if (err < 0) 
        return err;
    kamprobes_init(200);

    cdev_init(&cdev, &f_ops);
    cdev.owner = THIS_MODULE;
    cdev.ops = &f_ops;
    err = cdev_add(&cdev, MKDEV(major,0), 1);
    if (err) {
        unregister_major_num();
        return err;
    }

    printk(KERN_INFO MODULE_NAME": loaded, traced_caller: %px\n", traced_caller);
	return 0;
}

static void __exit test_victim_exit(void) {
    cdev_del(&cdev);
    unregister_major_num();
}

module_init(test_victim_init);
module_exit(test_victim_exit);
