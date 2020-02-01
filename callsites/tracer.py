from bcc import BPF

asm_volatile_goto_workarround = """
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#endif
#define volatile(x...) volatile("")
"""
bpf_header = asm_volatile_goto_workarround + """
#include <uapi/linux/ptrace.h>
BPF_HASH(rec_count, u32, u8, 1000);
BPF_HASH(relay, u32, u8, 1000);
BPF_HASH(probed, u64, u8, 10000);
BPF_PERF_OUTPUT(pipe);

struct msg  {
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
    u64 addr = (u64) ctx->ip;

    u8 *rc = rec_count.lookup(&tid);
    if (rc == NULL) {
        rec_count.insert(&tid,&zero);
        rc = rec_count.lookup(&tid);
        if (rc == NULL) return 1;
    }


    u8 *rel = relay.lookup(&tid);
    if (rel == NULL) {
        relay.insert(&tid,&zero);
        rel = relay.lookup(&tid);
        if (rel == NULL) return 1;
    }

    if (*rc == 0)
        *rel = 1;
    if (*rel == 0)
        return 1;
    *rc++;

    u8 *prob = probed.lookup(&addr);
    if (!prob)
        *rel = 0;
    
    struct msg m = {
        .addr = addr,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = true,
    };
    return pipe.perf_submit(ctx, &m, sizeof(m));
}

void initial_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u8 zero = 0;

    u8 *rc = rec_count.lookup(&tid);
    u8 *rel = relay.lookup(&tid);
    if (rel == NULL || rc == NULL) {
        return;
        //relay.insert(&tid,&zero);
        //rel = relay.lookup(&tid);
        //if (rel == NULL) return;
    }

    /*
    if (!rc) {
        *rel = 0;
        return;
    }
    */

    *rc--;

    struct msg m = {
        .addr = (u64) ctx->ip,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
    
    *rel = 1;
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

regs = ['ax','bx','cx','dx','si','di','bp','r8','r9','r10','r11','r12','r13','r14','r15']

regs_long = [reg if reg.startswith('r') else 'r'+reg for reg in regs]

regs_thunks = ["__x86_indirect_thunk_"+reg for reg in regs_long]

prog_texts = [non_initial_entry.replace("{REG}",reg) for reg in regs]

prog_text = bpf_header + initial_entry #+ "".join(prog_texts)
#print(prog_text)

calls_file = 'calls'
kallsyms_file = '/proc/kallsyms'
syms_file = 'System.map-5.3.0-26-generic'
from bisect import bisect
def init_call_graph():
    kallsyms = {}
    syms = []
    graph = {}
    thunks = {}
    with open(kallsyms_file, 'r') as kf:
        for l in kf.readlines():
            tok = l.split()
            if tok[1] in ['t','T']:
                kallsyms[tok[2]] = int(tok[0],16)
    with open(syms_file, 'r') as sf:
        for l in sf.readlines():
            tok = l.split()
            if tok[1] in ['t','T']:
                syms.append((int(tok[0],16),tok[2]))
    with open(calls_file, 'r') as cf:
        for l in cf.readlines():
            tok = l.split()
            addr = int(tok[0],16)
            target = int(tok[1],16)
            fun_id = bisect(syms,(addr,''))-1
            fun_addr = syms[fun_id][0]
            fun_name = syms[fun_id][1]
            runtime_fun = kallsyms[fun_name]
            runtime_addr = addr-fun_addr + runtime_fun
            runtime_target = kallsyms[syms[bisect(syms,(addr,''))-1][1]]
            if runtime_fun not in graph:
                graph[runtime_fun] = []
            graph[runtime_fun].append((runtime_addr, runtime_target))
    for i, reg in enumerate(regs):
        thunks[kallsyms["__x86_indirect_thunk_"+regs_long[i]]] = reg
    return graph, thunks

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

traced_functions = {}
queue = []
indent = 0
pipe = b['pipe']
probed = b['probed']


def process_message(cpu, data, size):
    message = pipe.event(data)
    print(" "*indent+b.ksym(message.addr))
    if message.addr not in traced_functions:
        queue.append(message.addr)
        traced_functions.insert(message.addr)

pipe.open_perf_buffer(process_message)
b.attach_kretprobe(event="",fn_name="initial_return")
b.attach_kprobe(event="",fn_name="initial_entry")

import ctypes
class UpdatesBuffer:
    lib = ctypes.CDLL("libkambpf.dll")
    def __init__(self, path):
        self._ptr = lib.kambpf_open_updates_device(path)
        self.probes = []
    def __del__(self):
        self.clear_probes()
        lib.kambpf_free_updates_buffer(self._ptr)
    def add_probes(self, probes):
        for i,probe in enumerate(probes):
            lib.kambpf_updates_set_entry(self._ptr, i, probe[0], probe[1], probe[2])
        lib.kambpf_submit_updates(self._ptr)
        for i in range(len(probes)):
            self.probes.append(lib.kambpf_updates_get_id(self._ptr, i))
    def clear_probes(self):
        for i, probe in enumerate(self.probes):
            lib.kambpf_updates_set_entry_remove(self._ptr, i, probe)
        self.probes = []

ub = UpdatesBuffer("/dev/kambpf_updates")
def add_probes(probes):
    ub.add_probes(probes)
    for p in probes:
        probed[p[0]] = 1

try:
    while True:
        b.perf_buffer_poll(100)
        new_probes = []
        for addr in queue:
            trace_function(addr, new_probes)
        add_probes(new_probes)
except KeyboardInterrupt:
    ub = None
    exit()

