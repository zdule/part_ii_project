#include "messages.h"
noinline long EPC_traced_caller(struct function_arguments *args);
#define EPC_call_address (((unsigned long long) EPC_traced_caller) + 0x26)
