from __future__ import print_function
from bcc import BPF
#from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
BPF_ARRAY(count, u32, 1);
int zdule_test(struct pt_regs *ctx, int num, char * str) {
    int id = 0;
    u32 *v = count.lookup(&id);
    if (v) {
        *v += num;
        bpf_trace_printk("%d %d %s\\n", num, *v, str);
    }
    return 0;
}
""")

b.attach_kprobe(event="sys_mkdir",fn_name="zdule_test")
fd = b.funcs.items()[0][1].fd
sysfile = open("/sys/module/simple_ebpf_run/parameters/prog",'w')
sysfile.write(str(fd))
sysfile.close()

#b.trace_print()
