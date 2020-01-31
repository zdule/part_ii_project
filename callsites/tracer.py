#from bcc import BPF

bpf_header = """
#include <uapi/linux/ptrace.h>
BPF_HASH(rec_count, u32, u8, 1000)
BPF_HASH(relay, u32, u8, 1000)
BPF_HASH(probed, u64, u8, 10000)
BPF_PERF_OUTPUT(pipe)

struct msg = {
    u64 addr;
    u64 nano;
    u32 tid;
    bool entry;
};
"""

initial_entry = """
int initial_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u8 zero = 0;

    u8 *rc = rec_count.lookup_or_try_init(&tid, &zero);
    if (rc == NULL) return 1;

    u8 *rel = relay.lookup_or_try_init(&tid,&zero);

    if (*rc == 0)
        *rel = 1;
    if (*rel == 0)
        return 1;
    *rc++;

    u8 *prob = probed.lookup(&ctx->ip);
    if (!prob)
        *rel = 0;
    
    struct msg m = {
        addr = ctx->ip,
        nano = bpf_ktime_get_ns(),
        tid = tid,
        entry = true,
    };
    return pipe.perf_submit(ctx, &m, sizeof(m));
}

void initial_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u8 zero = 0;

    u8 *rc = rec_count.lookup(&tid);
    u8 *rel = relay.lookup_or_try_init(&tid, &zero);
    if (!rc) {
        *rel = 0;
        return;
    }

    *rc--;

    struct msg m = {
        addr = {ADDR},
        nano = bpf_ktime_get_ns(),
        tid = tid,
        entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
    
    *rel = 1
    if (*rc == 0) {
        *rel = 0; 
    }
}
"""

# Any non-initial entry
# Parametrized by register name
# Direct calls get passed the target via r11
# Calls to spectre mitigation indirect jumps get
# passed the indirect address via a variety of registers

non_initial_entry = """
int non_initial_{REG}(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();

    u8 *rel = relay.lookup(&tid);
    if (!rel || *rel == 0) return 1;

    u8 *prob = probed.lookup(&ctx->{REG});
    if (!prob)
        *rel = 0;

    struct msg m = {
        addr = ctx->{REG},
        nano = bpf_ktime_get_ns(),
        tid = tid,
        entry = true,
    };
    return pipe.perf_submit(ctx, &m, sizeof(m));
}

void non_initial_{REG}_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();

    u8 *rel = relay.lookup(&tid);
    if (!rel) {
        return;
    }
    *rel = 1

    struct msg m = {
        addr = ctx->{REG},
        nano = bpf_ktime_get_ns(),
        tid = tid,
        entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
}
"""

regs = ['ax','bx','cx','dx','si','di','bp','r8','r9','r10','r11']#,'r12','r13','r14','r15']

regs_long = [reg if reg.startswith('r') else 'r'+reg for reg in regs]

regs_thunks = ["__x86_indirect_thunk_"+reg for reg in regs_long]

prog_texts = [non_initial_entry.replace("{REG}",reg) for reg in regs]

prog_text = bpf_header + initial_entry + "".join(prog_texts)
print(prog_text)

calls_file = 'calls'
kallsyms_file = '/proc/kallsyms'
syms_file = 'System.map-5.3.0-26-generic'
from bisect import bisect
def init_call_graph():
    kallsyms = {}
    syms = []
    with open(kallsyms_file, 'r') as kf:
        for l in kf.read().lines():
            tok = l.split()
            if tok[1] in ['t','T']:
                kallsyms[tok[2]] = tok[0]
    with open(syms_file, 'r') as sf:
        for l in kf.read().lines():
            tok = l.split()
            if tok[1] in ['t','T']:
                syms.append((int(tok[0]),tok[2]))
    with open(calls_file, 'r') as cf:
        for l in kf.read().lines():
            tok = l.split()
            addr = int(tok[0])
            target = int(tok[1])
            fun_id = bisect(syms,(addr,''))-1
            fun_addr = syms[fun_id][0]
            runtime_fun = kallsyms[syms[fun_id][1]]
            runtime_addr = addr-fun + runtime_fun_addr
            runtime_target = kallsyms[syms[bisect(syms,(addr,''))-1][1]]
            if runtime_fun not in graph:
                graph[runtime_fun] = []
            graph[runtime_fun].append((runtime_addr, runtime_target))
            

# graph maps funciton addresses to lists of (call_address, target)
# thunks maps addresses of spectre mitigation retpolines to registers they use
graph, thunks = init_call_graph()

b = BPF(text=prog_text)
def trace_function(address, queue):
    calls = graph[address]
    for (call_addr, target) in calls:
        if target in thunks:
            queue.append(call_addr, b.funcs[f"non_initial_{thunks[call_addr]}"].fd, funcs[f"non_initial_{thunks[call_addr]}_return"].fd)
        else:
            queue.append(call_addr, b.funcs["non_initial_r11"].fd, funcs["non_initial_r11_return"].fd)

import ctypes
import os
pth = os.path.dirname(os.path.abspath(__file__)) + "/build/user_main.so"
main = ctypes.CDLL(pth).main
main(fd,0)

traced_functions = {}
queue = []
indent = 0
pipe = b['pipe']
def process_message(cpu, data, size):
    message = pipe.event(data)
    print(" "*indent+b.ksym(message.addr))
    if message.addr not in traced_functions:
        queue.append(message.addr)
        traced_functions.insert(message.addr)

pipe.open_perf_buffer(process_message)

try:
    while True:
        b.perf_buffer_poll(100)
        new_probes = []
        for addr in queue:
            trace_function(addr, new_probes)
        

except KeyboardInterrupt:
    exit()

