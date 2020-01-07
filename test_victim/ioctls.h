#include "tests/entry_probe_correctness/messages.h"
#include <asm/ioctl.h>

#define KAMBPF_IOCTL_MAGIC '('

#define FUNCTION_N_PROGRAM(f,p) ((((unsigned long long) f) << 32L) | (p))
#define GET_FUNCTION(FNP) ((FNP)>>32L)
#define GET_PROGRAM(FNP) ((FNP) & ((1L<<32L)-1))

#define KAMBPF_SET_PROGRAM _IO(KAMBPF_IOCTL_MAGIC, 2)

#define KAMBPF_RUN_XOR10 _IOW(KAMBPF_IOCTL_MAGIC, 2, struct function_arguments)

enum function_ids {
    XOR10,
};

