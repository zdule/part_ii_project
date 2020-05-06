#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/kdev_t.h>	// dev_t macros
#include <linux/fs.h>		// registering devices, file operations
#include <linux/cdev.h>	
#include <linux/slab.h>		// kmalloc
#include <linux/errno.h>


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

#include "ioctls.h"
#include "tests/probes_correctness/kernel.h"
#include "tests/probes_safety/kernel.h"


long test_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO"ioctl\n");
    switch (cmd) {
		case IOCTL_GET_EPS:
		case IOCTL_RUN_EPS:
			printk(KERN_INFO"eps\n");
			return EPS_handle_ioctl(cmd,arg);
        case IOCTL_GET_EPC:
        case IOCTL_RUN_EPC:
            return EPC_handle_ioctl(cmd,arg);
        default:
            return -EINVAL;
    }
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

    cdev_init(&cdev, &f_ops);
    cdev.owner = THIS_MODULE;
    cdev.ops = &f_ops;
    err = cdev_add(&cdev, MKDEV(major,0), 1);
    if (err) {
        unregister_major_num();
        return err;
    }

	return 0;
}

static void __exit test_victim_exit(void) {
    cdev_del(&cdev);
    unregister_major_num();
}

module_init(test_victim_init);
module_exit(test_victim_exit);
