from dummy_probes import run_benchmark_with_dummies
from pathlib import Path
import argparse

def run_benchmark(output_folder, repetitions):
    def bench(mechanism, n_probes, run_id):
        print(mechanism, n_probes, run_id)
    run_benchmarks_with_dummies(bench, 50, 100, repetitions):

def main():
    parser = argparse.ArgumentParser(description='Run the low load latency benchmark with different number of dummy probes')
    parser.add_argument('--repetitions', type=int, default=5,
            help='Repetitions for a single tracing mechanism and number of probes')
    parser.add_argument('-o', type=str, default='~/measurements/default/',
            help='Folder in which to store log results')
    args = parser.parse_args()

    folder = Path(args.o) / "scalling_low_load_lat"
    makedirs(folder, exist_ok=True)
    run_benchmark(folder, args.repetitions)

