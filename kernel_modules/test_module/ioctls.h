/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#include "tests/probes_correctness/messages.h"
#include <asm/ioctl.h>

enum IOCTL_CODES {
    IOCTL_GET_EPC = 1234,
    IOCTL_RUN_EPC,
    IOCTL_GET_EPS,
    IOCTL_RUN_EPS,
};
