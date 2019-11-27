from __future__ import print_function
from bcc import BPF
#from bcc.utils import printb
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
BPF_HASH(calls, int);
BPF_STACK_TRACE(stack_traces, 1024);
BPF_ARRAY(count, u32, 1);
int zdule_test(struct pt_regs *ctx, int num, char * str) {
    int id = 0;
    u32 *v = count.lookup(&id);
    int key;
    key = stack_traces.get_stackid(ctx,BPF_F_REUSE_STACKID);
    if (key >= 0)
        calls.increment(key);
    if (v) {
        *v += num;
        bpf_trace_printk("%d %d %s\\n", num, *v, str);
    }
    return 0;
}
""")

b.attach_kprobe(event="sys_mkdir",fn_name="zdule_test")
fd = b.funcs.items()[0][1].fd

import ctypes
import os
pth = os.path.dirname(os.path.abspath(__file__)) + "/build/user_main.so"
main = ctypes.CDLL(pth).main
main(fd,0)

calls = b.get_table("calls")
stack_traces = b.get_table("stack_traces")

for k,v in calls.items():
    print()
    for addr in stack_traces.walk(k.value):
        print("HELLLO " + str(addr))
        print(b.ksym(addr, show_offset=True))

b.trace_print()
