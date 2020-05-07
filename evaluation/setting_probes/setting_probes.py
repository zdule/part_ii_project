#!/usr/bin/env python3

from random import shuffle
from os import makedirs, getenv, umask
from time import time
from pathlib import Path
import argparse

from pykambpf.dummy_probes import DummyProbes

DEFAULT_PATH = str(Path(getenv("project_dir")) / "measurements/default")

def timeit(f):
    ts = time() 
    f()
    te = time()
    return te-ts
    
def setting_probes_benchmark(step, max_probes, repetitions, outfile):
    experiments = [ (mechanism, probes) for probes in range(step, max_probes+1, step) for mechanism in ["kambpfprobes", "kprobes"]] * repetitions
    shuffle(experiments)
    results = []

    dummies = DummyProbes()
    n = len(experiments)
    for (i,(mechanism, probes)) in enumerate(experiments):
        print(f"Running  {i + 1} of {n}; {mechanism} {probes}")
       
        tmiddle = 0

        if mechanism == "kambpfprobes":
            dummies.reload_module()

        tstart = time()
        if mechanism == "kambpfprobes":
            dummies.set_kambpf_probes(probes)
            tmiddle = time()
            dummies.clear_kambpf_probes(probes)
        else:
            dummies.set_kprobes(probes)
            tmiddle = time()
            dummies.clear_kprobes(probes)
        tend = time()
        results.append((mechanism, probes, tmiddle-tstart, tend-tmiddle))
    dummies.cleanupBPF()

    print("mechanism,n_probes,set_time,release_time", file=outfile)
    print("\n".join([f"{mechanism}, {probes}, {tset}, {trelease}" for (mechanism, probes, tset, trelease) in results]), file=outfile)

def main():
    umask(0)

    parser = argparse.ArgumentParser(description='Measure time taken to set probes')
    parser.add_argument('--repetitions', type=int, default=20,
            help='Repetitions for a single tracing mechanism and number of probes')
    parser.add_argument('-o', type=str, default=DEFAULT_PATH,
            help='Folder in which to store log results')
    args = parser.parse_args()
    
    folder = Path(args.o) / "setting_probes"
    makedirs(folder, exist_ok=True)
    setting_probes_benchmark(250, 5000, args.repetitions, open(folder / "results.csv", 'w'))

if __name__ == "__main__":
    main()

