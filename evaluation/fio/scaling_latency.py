from dummy_probes import run_benchmarks_with_dummies
from fio_helper import run_traced_fio
from pathlib import Path
import argparse
from os import makedirs

def run_benchmark(output_folder, repetitions):
    def bench(mechanism, n_probes, run_id):
        print(mechanism, n_probes, run_id)
        log_path = output_folder / f"{mechanism}-{n_probes}-{run_id}.json" 
        run_traced_fio(mechanism, "low_load_latency.fio", log_path, log_type='json')
    run_benchmarks_with_dummies(bench, 50, 100, repetitions)

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

if __name__ == "__main__":
    main()

