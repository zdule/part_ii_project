#!/usr/bin/env python3
from subprocess import Popen, PIPE, run
import subprocess
from signal import sigwait, SIGUSR1, SIG_BLOCK, pthread_sigmask, SIG_SETMASK
from os import getpid, makedirs
import argparse
import datetime
from random import shuffle

class TracedContext:
    def __init__(self, probing_mechanism):
        self.mech = probing_mechanism
        self.tracer = None

    def __enter__(self):
        if self.mech in {'kprobes', 'kambpfprobes'}:
            old_mask = pthread_sigmask(SIG_BLOCK, {SIGUSR1})
            self.tracer = Popen(['sudo', 'python3', 'trace_io_uring.py', self.mech, '--parent-pid', str(getpid())], start_new_session=True)
            sigwait({SIGUSR1}) 
            pthread_sigmask(SIG_SETMASK, old_mask)
        
    def __exit__(self, exc_type, exc_value, traceback):
        if self.tracer != None:
            print(f'killing tracer {self.tracer.pid}')
            run(['sudo', 'kill', '-s', 'SIGINT',  str(self.tracer.pid)])

def single_round(probing_mechanism, output_path):
    with TracedContext(probing_mechanism):
        fio = run(['fio', 'fio_job.txt', '--output', output_path, '--output-format', 'json+'])

def run_rounds(folder, num_rounds):
    experiments = [ (probes, i) for i in range(num_rounds) for probes in ["no_probes", "kprobes", "kambpfprobes"]]
    shuffle(experiments)

    for i,e in enumerate(experiments):
        print(f"Running round {i+1}/{len(experiments)}")
        single_round(e[0], folder+e[0]+'-'+str(e[1])+'.json') 

parser = argparse.ArgumentParser(description='Run fio benchmark with different tracing mechanisms')
parser.add_argument('--repetitions', type=int, default=5,
        help='How many times to run each tracer')
parser.add_argument('-o', type=str, default='measurements/',
        help='Folder in which to store log results')
args = parser.parse_args()

folder = args.o + str(datetime.datetime.now()) + "/"
makedirs(folder, exist_ok=True)
run_rounds(folder, args.repetitions)

