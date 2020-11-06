#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

from pykambpf.dummy_probes import DummyProbes
from fio_helper import run_fio
from pathlib import Path
import argparse
from os import makedirs, getenv, umask
from pykambpf import UpdatesBuffer
from trace_io_uring import IOUringTracer
from subprocess import Popen

DEFAULT_PATH = str(Path(getenv("project_dir")) / "measurements/default")

def increasing_probes(mechanism, max_probes, step, repetitions, output_folder, fio_file):
    tracer = IOUringTracer()
    tracer.add_probes(mechanism)
    dummies = DummyProbes()

    n_prev = 0
    for n_probes in range(0,max_probes+1, step):
        print(f"Setting {mechanism} {n_probes}")
        if n_probes > 0:
            if mechanism == "kprobes":
                for probe_id in range(n_prev,n_probes):
                    dummies.b.attach_kprobe(event=f"0x{dummies.dummy_calls[probe_id]:x}", fn_name="test_fun")
            else:
                ub = UpdatesBuffer(n_probes)
                ub.add_probes([(addr,dummies.fd, -1) for addr in dummies.dummy_calls[n_prev:n_probes]])
                ub.close()

        print(f"Measuring {mechanism} {n_probes}")

        for run_id in range(repetitions):
            log_path = output_folder / f"mechanism-{mechanism}_nprobes-{n_probes}_runid-{run_id}.json" 
            fio = Popen(['fio', fio_file, '--output', log_path, '--output-format', 'json'])
            while True:
                for _ in range(20):
                    tracer.receive_messages()
                if fio.poll() != None:
                    break 
        n_prev = n_probes

    tracer.close()
    if mechanism == "kprobes":
        dummies.clear_kprobes(max_probes)
    else:
        dummies.clear_kambpf_probes(max_probes)    
    dummies.cleanupBPF()

def main():
    umask(0)

    parser = argparse.ArgumentParser(description='Run the low load latency benchmark with different number of dummy probes')
    parser.add_argument('benchmark', type=str, help='Either "latency" or "bandwidth"')
    parser.add_argument('--repetitions', type=int, default=5,
            help='Repetitions for a single tracing mechanism and number of probes')
    parser.add_argument('-o', type=str, default=DEFAULT_PATH,
            help='Folder in which to store log results')
    args = parser.parse_args()
    
    benchmarks_config = { 
        "latency" : { "subfolder" : "scaling_latency", "fio_file" : "low_load_latency.fio"},
        "bandwidth" : { "subfolder" : "scaling_bandwidth", "fio_file" : "bandwidth.fio"} }
    config = benchmarks_config[args.benchmark]

    folder = Path(args.o) / config["subfolder"]
    makedirs(folder, exist_ok=True)

    for mechanism in [ "kprobes"]:
        increasing_probes(mechanism, 5000, 250, args.repetitions, folder, config["fio_file"])

if __name__ == "__main__":
    main()
