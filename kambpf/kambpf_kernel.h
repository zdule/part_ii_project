#ifndef KAMBPF_KERNEL_H
#define KAMBPF_KERNEL_H

struct _probe_table_empty_entry {
    u32 table_pos;
    struct list_head empty_entries;    
};

#include "libkambpf/kambpf.h"

#endif // KAMBPF_KERNEL_H
