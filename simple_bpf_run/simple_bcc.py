from __future__ import print_function
from bcc import BPF
#from bcc.utils import printb

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

addrfile = open("/sys/module/simple_ebpf_run/parameters/test_address", 'r')
addr = addrfile.readline().strip()
addrfile.close()

sysfile = open("/sys/module/simple_ebpf_run/parameters/probe",'w')
sysfile.write(addr + " " + str(fd))
sysfile.close()

triggerfile = open("/sys/module/simple_ebpf_run/parameters/trigger",'w')
triggerfile.write("\n")
triggerfile.close()

#b.trace_print()
