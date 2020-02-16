import sys
from call_graph import CallGraph
from bcc import BPF
import os
from signal import SIGUSR1

def add_kambpfprobes(probes, b):
    from libkambpf import UpdatesBuffer
    ub = UpdatesBuffer()
    ub.add_probes([(p[0],b.funcs[p[1]].fd,-1) for p in probes])
    return ub

def add_kprobes(probes, b):
    for p in probes:
        b.attach_kprobe(event=f"0x{p[0]:x}",fn_name=p[1])
    return None

add_probes = {
    "kambpfprobes" : add_kambpfprobes,
    "kprobes" : add_kprobes,
}
        
import argparse
parser = argparse.ArgumentParser(description='Instrument requests handling in io_uring')
parser.add_argument('probes', type=str, nargs='?', 
        default=list(add_probes.keys())[0], choices=add_probes.keys(),
        help='A tracing mechanism to use.')
parser.add_argument('--parent-pid', type=int, dest='parent_pid',
        help='The pid of the process to receive SIGUSR1 when we have set up probes')
args = parser.parse_args()

prog_text = open('trace_io_uring_bpf.c', 'r').read()

graph = CallGraph()
io_queue_work_on_addr = graph.get_edges_sites("io_queue_sqe","queue_work_on")[0]
io_complete_r_addr = graph.indirect_calls_from_fun("io_read")[1][0]
io_complete_w_addr = graph.indirect_calls_from_fun("io_write")[1][0]
io_submit_sqe_addr = graph.get_edges_sites("io_sq_wq_submit_work","__io_submit_sqe")[0]

b = BPF(text=prog_text)
b.load_funcs()


import ctypes as ct
class Message(ct.Structure):
    _fields_ = [("queue_entry", ct.c_uint64),
                ("op_start", ct.c_uint64),
                ("completion", ct.c_uint64),]

def process_message(cpu, data, size):
    message = ct.cast(data, ct.POINTER(Message)).contents
    total = message.completion-message.queue_entry
    pre_submit = message.op_start - message.queue_entry
    op_length = message.completion - message.op_start
    print("lat :" + str(total))
    print(f"split: in queue {100*pre_submit/total}%, op {100*op_length/total}%")

pipe = b['pipe']
pipe.open_perf_buffer(process_message)

# token should not be garbage collected
token = add_probes[args.probes]([
    (io_queue_work_on_addr, "tt_queue_work_on"),
    (io_complete_r_addr, "tt_complete_rw"),
    (io_complete_w_addr, "tt_complete_rw"),
    (io_submit_sqe_addr, "tt_submit_sqe"),
], b)

print("Attached probes")
if args.parent_pid:
    os.kill(args.parent_pid, SIGUSR1)

from time import sleep

while True:
    b.kprobe_poll(100)
