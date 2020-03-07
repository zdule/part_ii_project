#include "tests/entry_probe_correctness/messages.h"
#include <asm/ioctl.h>

enum IOCTL_CODES {
    IOCTL_GET_EPC = 1234,
    IOCTL_RUN_EPC,
    IOCTL_GET_EPS,
    IOCTL_RUN_EPS,
};
