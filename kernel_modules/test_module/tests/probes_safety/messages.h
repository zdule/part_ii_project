/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#ifndef TEST_ENTRY_PROBE_SAFETY_MESSAGESS_H
#define TEST_ENTRY_PROBE_SAFETY_MESSAGESS_H

enum control_indices {
    CALLER_TOP_OF_STACK,
    CALLEE_TOP_OF_STACK,
    RETURN_VALUE_1,
    RETURN_VALUE_2,
    RBP,
    R12,
    R13,
    R14,
    R15, 
    RSI,
    RDX,
    RCX,
    R8,
    R9,
    GRAND_OUT_RETURN_VALUE,
    CONTROL_BLOCK_SIZE,
};

/*
enum control_indices {
    IN_ARGUMENT_REGISTER,
    IN_TOP_OF_THE_STACK,
    IN_CALLEE_SAVED_REGISTER,
    IN_RETURN_VALUE,
    CALLEE_OUT_ARGUMENT_REGISTER,
    CALLEE_OUT_TOP_OF_THE_STACK,
    CALLEE_OUT_CALLEE_SAVED_REGISTER,
    CALLER_OUT_TOP_OF_THE_STACK,
    CALLER_OUT_CALLEE_SAVED_REGISTER, 
    CALLER_OUT_RETURN_VALUE,
    GRAND_OUT_RETURN_VALUE,

    CONTROL_BLOCK_SIZE,
};
*/

typedef __u64 control_block_t[CONTROL_BLOCK_SIZE];

#endif
