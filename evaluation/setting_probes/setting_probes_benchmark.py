#!/usr/bin/env python3

from bcc import BPF
from pykambpf import UpdatesBuffer, CallGraph
from random import shuffle
import subprocess
import os
from time import time
import datetime
from pathlib import Path

PATH_TO_TEST_MODULE = "../../kernel_modules/test_victim/build/test_victim_main.ko"
dummy_name_pattern = "kambpf_test_dummy_{}"
prog_text = """
int test_fun(struct pt_regs *ctx) {
    return 0;
}
"""


b = BPF(text=prog_text)
b.load_funcs()
fd = b.funcs['test_fun'].fd

def find_addresses(call_graph, n):
    results = []
    for i in range(1, n):
        results.extend(call_graph.calls_from_fun(dummy_name_pattern.format(i))[1:])
    results = [tup[0] for tup in results]
    return results

def attach_kamprobes(call_graph, n):
    ub = UpdatesBuffer(n)
    addrs = find_addresses(call_graph, n)
    ub.add_probes([(addr, fd, -1) for addr in addrs])
    ub.clear_probes()

def attach_kprobes(call_graph, n):
    global b
    addrs = find_addresses(call_graph, n)
    for addr in addrs:
        b.attach_kprobe(event=f"0x{addr:x}", fn_name="test_fun")
    for addr in addrs:
        b.detach_kprobe(event=f"0x{addr:x}")

def reload_module():
    subprocess.run([os.getenv("kambpf_reload"), "unload"])
    subprocess.run([os.getenv("kamprobes_reload"), "unload"])
    subprocess.run([os.getenv("kamprobes_reload"), "load"])
    subprocess.run([os.getenv("kambpf_reload"), "load"])

def timeit(f):
    ts = time() 
    f()
    te = time()
    return te-ts

def run_tests(step, max_probes, repetitions, outfile):
    experiments = [ (mechanism, probes) for probes in range(step, max_probes, step) for mechanism in ["kamprobes", "kprobes"]] * repetitions
    shuffle(experiments)
    results = []
    reload_module()

    call_graph = CallGraph()
    call_graph.parse_module(PATH_TO_TEST_MODULE)

    n = len(experiments)
    for (i,(mechanism, probes)) in enumerate(experiments):
        print(f"Running  {i + 1} of {n}; {mechanism} {probes}")
        if mechanism == "kamprobes":
            t = timeit(lambda : attach_kamprobes(call_graph, probes))
            reload_module()
        else:
            t = timeit(lambda : attach_kprobes(call_graph, probes))
        results.append((mechanism, probes, t))

    print("mechanism,n_probes,time", file=outfile)
    print("\n".join([f"{mechanism}, {probes}, {t}" for (mechanism, probes, t) in results]), file=outfile)

if __name__== "__main__":
    os.makedirs('results/', exist_ok=True)
    filename = f"{datetime.datetime.now()}.csv"
    f = open("results/" + filename, 'w')
    run_tests(50,1000,5,f)
    latest = Path('results/latest.csv')
    if latest.is_symlink():
        latest.unlink()
    latest.symlink_to(filename)
