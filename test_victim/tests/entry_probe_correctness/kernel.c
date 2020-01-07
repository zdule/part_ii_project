#include "kernel.h"

noinline u64 EPC_traced_function(u64 arg1, u64 arg2, u64 arg3, u64 arg4, 
                             u64 arg5, u64 arg6, u64 arg7, u64 arg8) {
    return arg1 ^ arg2 ^ arg3 ^ arg4 ^ arg5 ^ arg6 ^ arg7 ^ arg8;
}

noinline long EPC_traced_caller(struct function_arguments *args) {
    return EPC_traced_function(args->arg1, args->arg2, args->arg3, args->arg4,
                               args->arg5, args->arg6, args->arg7, args->arg8);
}

