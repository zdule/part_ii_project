#!/usr/bin/env python3

from call_graph import CallGraph
from bcc import BPF
from libkambpf import UpdatesBuffer

PATH_TO_TEST_MODULE = "../kambpf/build/kambpf.ko"
dummy_name_pattern = "kambpf_test_dummy_{}"

call_graph = CallGraph()
call_graph.parse_module(PATH_TO_TEST_MODULE)

def find_addresses():
    global call_graph
    return call_graph.calls_from(dummy_name_pattern.format(1))

def attach_kprobes():
    pass

def setup_callgraph():
    pass

if __name__== "__main__":
    print(find_addresses())
