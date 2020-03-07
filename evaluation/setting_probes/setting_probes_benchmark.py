#!/usr/bin/env python3

from bcc import BPF
from pykambpf import UpdatesBuffer, CallGraph
from random import shuffle
import subprocess
import os

PATH_TO_TEST_MODULE = "../../kernel_modules/test_victim/build/test_victim_main.ko"
dummy_name_pattern = "kambpf_test_dummy_{}"
prog_text = """
int test_fun(struct pt_regs *ctx) {
    return 0;
}
"""

call_graph = CallGraph()
call_graph.parse_module(PATH_TO_TEST_MODULE)

b = BPF(text=prog_text)
b.load_funcs()
fd = b.funcs['test_fun'].fd

def find_addresses(call_graph, n):
    results = []
    for i in range(1, n):
        results.extend(call_graph.calls_from_fun(dummy_name_pattern.format(i))[1:])
    results = [tup[0] for tup in results]
    return results

def attach_kamprobes(call_graph):
    ub = UpdatesBuffer()
    addrs = find_addresses(call_graph, 5)
    ub.add_probes([(addr, fd, -1) for addr in addrs])
    ub.remove_probes(addrs)

def attach_kprobes(call_graph):
    global b
    addrs = find_addresses(call_graph, 1000)
    for addr in addrs:
        print(f"0x{addr:x}")
        b.attach_kprobe(event=f"0x{addr:x}", fn_name="test_fun")
    for addr in addrs:
        b.detach_kprobe(event=f"0x{addr:x}")

def reload_module():
	subprocess.run([os.getenv("kamprobes_reload"), "unload"])
	subprocess.run([os.getenv("kambpf_reload"), "load"])

def run_tests(step, max_probes, repetitions):
	experiments = [ (mechanism, probes) for probes in range(step, max_probes, step) for mechanism in ["kprobes", "kamprobes"]] * repetitions
	shuffle(experiments)
	reload_module()

	for (mechanism, probes) in experiments:
		print(mechanism, probes)

if __name__== "__main__":
	run_tests(5,20,2)
