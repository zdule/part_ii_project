from __future__ import print_function
from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
int zdule_test(struct pt_regs *ctx) {
    bpf_trace_printk("Hello\\n");
    return 0;
}
""")

b.attach_kprobe(event="sys_mkdir",fn_name="zdule_test")
fd = b.funcs.items()[0][1].fd

sysfile = open("/sys/module/simple_ebpf_run/parameters/probe",'w')
sysfile.write(str(fd))
sysfile.close()

b.trace_print()
