#!/usr/bin/env python3

from random import shuffle
from os import makedirs, getenv, umask
from time import time
from pathlib import Path

from pykambpf.dummy_probes import run_benchmarks_with_dummies

DEFAULT_PATH = str(Path(getenv("project_dir")) / "measurements/default")

def timeit(f):
    ts = time() 
    f()
    te = time()
    return te-ts

def tripass(a,b,c):
    pass

def setting_probes_benchmark(step, max_probes, repetitions, outfile):
    experiments = [ (mechanism, probes) for probes in range(step, max_probes, step) for mechanism in ["kambpfprobes", "kprobes"]] * repetitions
    shuffle(experiments)
    results = []

    dummies = DumyProbes()
    n = len(experiments)
    for (i,(mechanism, probes)) in enumerate(experiments):
        print(f"Running  {i + 1} of {n}; {mechanism} {probes}")
        
        if mechanism == "kambpfprobes":
            t = timeit(lambda : dummies.with_kambpf_probes(tripass, probes, 0, ""))
        else:
            t = timeit(lambda : dummies.with_kprobes(tripass, probes, 0, ""))
        results.append((mechanism, probes, t))

    print("mechanism,n_probes,time", file=outfile)
    print("\n".join([f"{mechanism}, {probes}, {t}" for (mechanism, probes, t) in results]), file=outfile)

def main():
    umask(0)

    parser = argparse.ArgumentParser(description='Measure time taken to set probes')
    parser.add_argument('--repetitions', type=int, default=6,
            help='Repetitions for a single tracing mechanism and number of probes')
    parser.add_argument('-o', type=str, default=DEFAULT_PATH,
            help='Folder in which to store log results')
    args = parser.parse_args()
    
    folder = Path(args.o) / "setting_probes"
    makedirs(folder, exist_ok=True)
    setting_probes_benchmark(50, 1000, args.repetitions, folder / "results.csv")

if __name__ == "__main__":
    main()

