/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

#ifndef KAMBPF_KERNEL_H
#define KAMBPF_KERNEL_H

struct _probe_table_empty_entry {
    u32 table_pos;
    struct list_head empty_entries;    
};

#include "libkambpf/kambpf.h"

#endif // KAMBPF_KERNEL_H
