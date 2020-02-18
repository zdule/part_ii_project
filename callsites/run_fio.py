#!/usr/bin/env python3
from subprocess import Popen, PIPE, run
import subprocess
from signal import sigwait, SIGUSR1, SIG_BLOCK, pthread_sigmask, SIG_SETMASK
from os import getpid, makedirs
import argparse
import datetime
from random import shuffle
from pathlib import Path

from trace_io_uring import IOUringTracer

def run_rounds(folder, num_rounds):
    experiments = [ probes for _ in range(num_rounds) for probes in ["no_probes", "kprobes", "kambpfprobes"]]
    shuffle(experiments)

    tracer = IOUringTracer()
    for i,probing_mechanism in enumerate(experiments):
        print(f"Running round {i+1}/{len(experiments)}")

        tracer.add_probes(probing_mechanism)
        
        output_path = folder / f"{probing_mechanism}-{i}.json"
        fio = Popen(['fio', 'fio_job.txt', '--output', output_path, '--output-format', 'json+'])

        while True:
            for _ in range(20):
                tracer.receive_messages()
            if fio.poll() != None:
                break 

        tracer.remove_probes()

parser = argparse.ArgumentParser(description='Run fio benchmark with different tracing mechanisms')
parser.add_argument('--repetitions', type=int, default=5,
        help='How many times to run each tracer')
parser.add_argument('-o', type=str, default='measurements/',
        help='Folder in which to store log results')
args = parser.parse_args()

folder = Path(args.o) / str(datetime.datetime.now())
makedirs(folder, exist_ok=True)
latest = Path(args.o) / 'latest'
if latest.is_symlink():
    latest.unlink()
latest.symlink_to(folder.name)
run_rounds(folder, args.repetitions)

