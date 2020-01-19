#ifndef TEST_ENTRY_PROBE_CORRECTNESS_MESSAGESS_H
#define TEST_ENTRY_PROBE_CORRECTNESS_MESSAGESS_H

#ifdef __KERNEL__ 
    #include <linux/types.h>
    #define __u64 u64
    #define __u32 u32
#endif 

struct function_arguments {
    __u64 arg1; // register: rdi
    __u64 arg2; // register: rsi
    __u64 arg3; // register: rdx
    __u64 arg4; // register: rcx
    __u64 arg5; // register: r8
    __u64 arg6; // register: r9
    __u64 arg7; // stack argument
    __u64 arg8; // stack argument
};

struct entry_probe_correctness_message {
    struct function_arguments args;
    __u64 stack_id; 
};

struct return_probe_correctness_message {
    __u64 return_value; 
    __u64 stack_id;
};


#ifdef __KERNEL__ 
    #undef __u64
    #undef __u32
#endif 

#endif
