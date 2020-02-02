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
//BPF_TABLE_SHARED("hash", u32, u8, rec_count, 1000);
//BPF_TABLE_SHARED("hash", u32, u8, relay, 1000);
//BPF_TABLE_SHARED("hash", u64, u8, probed, 10000);
BPF_HASH(rec_count, u32, u8, 1000);
BPF_HASH(relay, u32, u8, 1000);
BPF_HASH(probed, u64, u8, 10000);
BPF_PERF_OUTPUT(pipe);

struct msg  {
    u64 addr;
    u64 nano;
    u32 tid;
    u32 entry;
};
"""

initial_entry = """
int initial_entry(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    u8 zero = 0;
    u64 addr = (u64) ctx->ip;
    bpf_trace_printk("Initial entry %d\\n",tid);

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

    //if (*rc == 0)
        *rel = 1;
    if (*rel == 0)
        return 1;
    (*rc)++;

    //u8 *prob = probed.lookup(&addr);
    //if (!prob)
    //    *rel = 0;

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
    if (rel == NULL || rc == NULL) 
        return;

    (*rc)--;

    struct msg m = {
        .addr = (u64) ctx->ip,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
    
    *rel = 1;
    if (*rc == 0) {
        //*rel = 0; 
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

    u64 target = (u64) ctx->{REG};

    u8 *prob = probed.lookup(&target);
    if (!prob)
        *rel = 0;

    struct msg m = {
        .addr = target,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = true,
    };
    return pipe.perf_submit(ctx, &m, sizeof(m));
}

void non_initial_{REG}_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();

    u8 *rel = relay.lookup(&tid);
    if (!rel) {
        return;
    }
    *rel = 1;

    struct msg m = {
        .addr = (u64) ctx->{REG},
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
}
"""
non_initial_callq = """
int non_initial_callq(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();
    bpf_trace_printk("Initial callq %d\\n",tid);

    u8 *rel = relay.lookup(&tid);
    if (!rel) return 1;
    if (*rel == 0)
        return 1;
    bpf_trace_printk("triggered mwprobe\\n");

    u32 offset = 0;
    u64 target = (u64) ctx->ip;
    if (bpf_probe_read(&offset, 4, (u64*)(ctx->ip+1)) != 0)
        return 1;
    target += offset;
    bpf_trace_printk("triggered mfprobe\\n");
    u8 *prob = probed.lookup(&target);
    if (!prob)
        *rel = 0;

    bpf_trace_printk("triggered maprobe\\n");
    struct msg m = {
        .addr = target,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = true,
    };
    return pipe.perf_submit(ctx, &m, sizeof(m));
}

void non_initial_callq_return(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid();

    u8 *rel = relay.lookup(&tid);
    if (!rel) {
        return;
    }
    *rel = 1;

    u32 offset = 0;
    u64 target = (u64) ctx->ip;
    if (bpf_probe_read(&offset, 4, (u64*)(ctx->ip+1)) != 0)
        return;
    target += offset;

    struct msg m = {
        .addr = target,
        .nano = bpf_ktime_get_ns(),
        .tid = tid,
        .entry = false,
    };
    pipe.perf_submit(ctx, &m, sizeof(m));
}
"""

regs = ['ax','bx','cx','dx','si','di','bp','r8','r9','r10','r11','r12','r13','r14','r15']

regs_long = [reg if reg.startswith('r') else 'r'+reg for reg in regs]

regs_thunks = ["__x86_indirect_thunk_"+reg for reg in regs_long]

prog_texts = [non_initial_entry.replace("{REG}",reg) for reg in regs]

prog_text = bpf_header + initial_entry + "".join(prog_texts) + non_initial_callq 
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
print("hi")
graph, thunks = init_call_graph()

print("hi")
b = BPF(text=prog_text)
b.load_funcs()
print("hi load")

def trace_function(address, queue):
    if address not in graph:
        print(f"Address not found in graph {address:x}")
        return
    calls = graph[address]
    for (call_addr, target) in calls:
        if target in thunks:
            queue.append((call_addr, b.funcs[f"non_initial_{thunks[call_addr]}"].fd, b.funcs[f"non_initial_{thunks[call_addr]}_return"].fd))
        else:
            queue.append((call_addr, b.funcs["non_initial_r11"].fd, b.funcs["non_initial_r11_return"].fd))

traced_functions = set()
queue = []
indent = 0
pipe = b['pipe']
probed = b['probed']

import ctypes as ct
class Message(ct.Structure):
    _fields_ = [("addr", ct.c_uint64),
                ("nano", ct.c_uint64),
                ("tid", ct.c_uint32),
                ("entry",ct.c_uint32),]

def process_message(cpu, data, size):
    global indent
    message = ct.cast(data, ct.POINTER(Message)).contents
    print(" "*indent+b.ksym(message.addr) + f"{message.addr:x}")
    if message.entry > 0:
        indent += 1
    else:
        indent -= 1
    if message.addr not in traced_functions:
        print(f"processin {message.addr:x}")
        queue.append(message.addr)
        traced_functions.add(message.addr)

pipe.open_perf_buffer(process_message)
entry_point = "__x64_sys_io_uring_enter"
b.attach_kretprobe(event=entry_point,fn_name="initial_return")
b.attach_kprobe(event=entry_point,fn_name="initial_entry")

from libkambpf import UpdatesBuffer

ub = UpdatesBuffer(b"/dev/kambpf_update")
def add_probes(probes):
    ub.add_probes(probes)
    for p in probes:
        probed[ct.c_uint64(p[0])] = ct.c_uint8(1)

print("hi")
q123 = []
trace_function(b.ksymname(entry_point),q123)
print(graph[b.ksymname(entry_point)])
print(q123)
add_probes(q123)
probed[ct.c_uint64(b.ksymname(entry_point))] = ct.c_uint8(1)
probed[ct.c_uint64(b.ksymname(entry_point)+1)] = ct.c_uint8(1)

print(ub.probes)
try:
    while True:
        b.kprobe_poll(100)
        new_probes = []
#for addr in queue:
#trace_function(addr, new_probes)
#add_probes(new_probes)
except:
    print('exiting')
    ub.clear_probes()
    ub = None
    exit()

