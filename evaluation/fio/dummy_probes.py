from bcc import BPF
from pykambpf import UpdatesBuffer, CallGraph
from random import shuffle
import subprocess
import os
from time import time
from pathlib import Path

def reload_module():
    subprocess.run([os.getenv("kambpf_reload"), "unload"])
    subprocess.run([os.getenv("kamprobes_reload"), "unload"])
    subprocess.run([os.getenv("kamprobes_reload"), "load"])
    subprocess.run([os.getenv("kambpf_reload"), "load"])

PATH_TO_TEST_MODULE = "../../kernel_modules/test_victim/build/test_victim_main.ko"
dummy_name_pattern = "kambpf_test_dummy_{}"
prog_text = """
int test_fun(struct pt_regs *ctx) {
    return 0;
}
"""

class DummyProbes():
    def __init__(self, call_graph = None, updates_buffer = None, max_probes = 1000):
        if call_graph = None:
            call_graph = CallGraph()
            call_graph.parse_module(PATH_TO_TEST_MODULE)
        self.graph = call_graph

        self.dummy_calls = DummyProbes.find_addresses(self.graph, max_probes)

        self.b = BPF(text=prog_text)
        self.b.load_funcs()
        self.fd = self.b.funcs['test_fun'].fd

    def find_addresses(call_graph, n):
        results = []
        for i in range(1, n):
            results.extend(call_graph.calls_from_fun(dummy_name_pattern.format(i))[1:])
        results = [tup[0] for tup in results]
        return results

    def with_kambpf_probes(self, n, run_id, function):
        reload_module()
        ub = UpdatesBuffer(n)
        ub.add_probes([(addr, fd, -1) for addr in self.dummy_calls])
        function("kambpfprobes", n, run_id)
        ub.clear_probes()

    def with_kprobes(self, n, run_id, function):
        for addr in self.dummy_calls:
            self.b.attach_kprobe(event=f"0x{addr:x}", fn_name="test_fun")
        function("kprobes", n, run_id)
        for addr in self.dummy_calls:
            self.b.detach_kprobe(event=f"0x{addr:x}")


def run_benchmarks_with_dummies(bench, step, max_probes, repetitions=1):
    """
        Run a benchmark with different number of dummy probes set on the test module.

        The runs of the benchmark are shuffeled between the two mechanisms and repetitions
        for the same number of dummy probes.
        
        param bench: Benchmark funciton to run. Takes three arguments. 
                     First argument is the probing mechanism which was used (one of kprobes, kambpfprobes). 
                     Second argument is the number of probes set. Third argument repetition number for this config.
        param step: Step increase in number of dummy probes.
        param max_probes: Maximal number of dummy probes, inclusive.
        param repetitions: How many times to run a benchmark with same number of dummy probes and same mech.
    """

    dummies = DummyProbes()
    runners = [dummies.with_kambpf_probes, dummies.with_kprobes]
    for n_probes in range(0,step,max_probes+1):
        experimetns = [0,1]*repetitions 
        shuffle(experiments)
        run_count = { 0 : 0, 1 : 0}
        for r in experiments:
            runner = runners[r]
            runner(n_probes, run_count[r], bench)
            run_count[r] += 1
