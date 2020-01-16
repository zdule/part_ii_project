#include <linux/uaccess.h>
#include "kernel.h"
#include "../../ioctls.h"

noinline u64 EPC_traced_function(u64 arg1, u64 arg2, u64 arg3, u64 arg4, 
                             u64 arg5, u64 arg6, u64 arg7, u64 arg8) {
    return arg1 ^ arg2 ^ arg3 ^ arg4 ^ arg5 ^ arg6 ^ arg7 ^ arg8;
}

noinline u64 EPC_traced_caller(struct function_arguments *args) {
    return EPC_traced_function(args->arg1, args->arg2, args->arg3, args->arg4,
                               args->arg5, args->arg6, args->arg7, args->arg8);
}

u64 EPC_call_address = ((u64) EPC_traced_caller) + 0x26;

long EPC_handle_ioctl(unsigned int cmd, unsigned long arg) {
    printk(KERN_INFO"correctness ioctl\n");
    if (cmd == IOCTL_GET_EPC) {
        copy_to_user((void *)arg, &EPC_call_address, sizeof(EPC_call_address));
        return 0;
    }
    else if (cmd == IOCTL_RUN_EPC) {
        struct function_arguments args;
        volatile u64 x;
        if (copy_from_user(&args, (void *)arg, sizeof(struct function_arguments)) != 0)
            return -EINVAL;
        x = EPC_traced_caller(&args);
        return 0;
    } else return -EINVAL;
}
