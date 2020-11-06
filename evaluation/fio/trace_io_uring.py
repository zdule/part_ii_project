#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

from pykambpf import CallGraph
from pykambpf import UpdatesBuffer

from bcc import BPF

import ctypes as ct

class Message(ct.Structure):
    _fields_ = [("queue_entry", ct.c_uint64),
                ("op_start", ct.c_uint64),
                ("completion", ct.c_uint64),]

def guard_closed(method):
    def wrapped(self, *args, **kwargs):
        if self.closed:
            raise Exception(f"The instance of {self.__class__.__name__} is closed")
        return method(self, *args, **kwargs)
    return wrapped

class IOUringTracer:
    def __init__(self, print_messages=False):
        self.closed = False
        self.ub = UpdatesBuffer()

        prog_text = open('trace_io_uring_bpf.c', 'r').read()
        self.graph = CallGraph()
        self.io_queue_work_on_addr = self.graph.get_edges_sites("io_queue_sqe","queue_work_on")[0]
        self.io_complete_r_addr = self.graph.indirect_calls_from_fun("io_read")[1][0]
        self.io_complete_w_addr = self.graph.indirect_calls_from_fun("io_write")[1][0]
        self.io_submit_sqe_addr = self.graph.get_edges_sites("io_sq_wq_submit_work","__io_submit_sqe")[0]

        self.b = BPF(text=prog_text)
        self.b.load_funcs()

        self.pipe = self.b['pipe']
        self.print_messages = print_messages
        self.pipe.open_perf_buffer(self.__process_message)
        
        self.probing_mechanisms = {
            "kambpfprobes" : self.add_kambpfprobes,
            "kprobes" : self.add_kprobes,
        }

        self.remove_probe_fns = []

    @guard_closed
    def add_kambpfprobes(self, probes):
        self.ub.add_probes([(p[0],self.b.funcs[p[1]].fd,-1) for p in probes])
        self.remove_probe_fns.append(lambda: self.ub.clear_probes())
        
    @guard_closed        
    def add_kprobes(self, probes):
        def get_remove_probe(name):
            return lambda: self.b.detach_kprobe(name)
        for p in probes:
            event = f"0x{p[0]:x}"
            self.b.attach_kprobe(event=event,fn_name=p[1])
            self.remove_probe_fns.append(get_remove_probe(event))


    @guard_closed
    def add_probes(self, mechanism):
        if mechanism == 'no_probes' or mechanism == "noprobes":
            return
        self.probing_mechanisms[mechanism]([
            (self.io_queue_work_on_addr, "tt_queue_work_on"),
            (self.io_complete_r_addr, "tt_complete_rw"),
            (self.io_complete_w_addr, "tt_complete_rw"),
            (self.io_submit_sqe_addr, "tt_submit_sqe"),
        ])

    def __process_message(self, cpu, data, size):
        message = ct.cast(data, ct.POINTER(Message)).contents
        total = message.completion-message.queue_entry
        pre_submit = message.op_start - message.queue_entry
        op_length = message.completion - message.op_start
        if self.print_messages:
            print("lat :" + str(total))
            print(f"split: in queue {100*pre_submit/total}%, op {100*op_length/total}%")

    @guard_closed
    def receive_messages(self):
        self.b.kprobe_poll(10)

    @guard_closed
    def remove_probes(self):
        for f in self.remove_probe_fns:
            f()
        self.remove_probe_fns = []

    def close(self):
        if self.closed:
            return
        self.remove_probes()
        self.ub.close()
        self.ub = None
        self.b.cleanup()
        self.b = None
        self.closed = True

    def __del__(self):
        self.close()
    
if __name__== "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Instrument requests handling in io_uring')
    parser.add_argument('probes', type=str, nargs='?', 
            default="kambpfprobes", choices=["kambpfprobes","kprobes"],
            help='A tracing mechanism to use.')
    args = parser.parse_args()

    tracer = IOUringTracer(True)
    tracer.add_probes(args.probes)
    while True:
        tracer.receive_messages()
