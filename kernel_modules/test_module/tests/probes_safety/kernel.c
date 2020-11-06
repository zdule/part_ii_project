/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include <linux/uaccess.h>
#include "kernel.h"
#include "../../ioctls.h"

#include "messages.h"

u64 EPS_traced_caller(control_block_t);
void EPS_call_instruction(void);

u64 EPS_call_address = (u64) EPS_call_instruction;

long EPS_handle_ioctl(unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO"safety\n");
    if (cmd == IOCTL_GET_EPS) {
		printk(KERN_INFO"addrs %llx\n",EPS_call_address);
        copy_to_user((void *)arg, &EPS_call_address, sizeof(EPS_call_address));
        return 0;
    }
    else if (cmd == IOCTL_RUN_EPS) {
        control_block_t control_block;
		printk(KERN_INFO"RUNNING\n");
        if (copy_from_user(control_block, (void *)arg, sizeof(control_block_t)) != 0)
            return -EINVAL;
        control_block[GRAND_OUT_RETURN_VALUE] = EPS_traced_caller(control_block);
        if (copy_to_user((void *) arg, control_block, sizeof(control_block_t)) != 0)
            return -EINVAL;
        return 0;
    } else return -EINVAL;
}
