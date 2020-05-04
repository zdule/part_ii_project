from dummy_probes import run_benchmarks_with_dummies
from fio_helper import run_traced_fio
from pathlib import Path
import argparse
from os import makedirs, getenv, umask

DEFAULT_PATH = str(Path(getenv("project_dir")) / "measurements/default")

def scaling_fio_benchmark(output_folder, repetitions, fio_file):
    def bench(mechanism, n_probes, run_id):
        print(mechanism, n_probes, run_id)
        log_path = output_folder / f"mechanism-{mechanism}_nprobes-{n_probes}_runid-{run_id}.json" 
        run_traced_fio(mechanism, fio_file, log_path, log_type='json')
    run_benchmarks_with_dummies(bench, 50, 1000, repetitions)

def main():
    umask(0)

    parser = argparse.ArgumentParser(description='Run the low load latency benchmark with different number of dummy probes')
    parser.add_argument('benchmark', type=str, help='Either "latency" or "bandwidth"')
    parser.add_argument('--repetitions', type=int, default=6,
            help='Repetitions for a single tracing mechanism and number of probes')
    parser.add_argument('-o', type=str, default=DEFAULT_PATH,
            help='Folder in which to store log results')
    args = parser.parse_args()
    
    benchmarks_config = { 
    	"latency" : { "subfolder" : "scaling_latency", "fio_file" : "low_load_latency.fio"},
    	"bandwidth" : { "subfolder" : "scaling_bandwidth", "fio_file" : "bandwdith.fio"} }
    config = benchmarks_config[args.benchmark]

    folder = Path(args.o) / config["subfolder"]
    makedirs(folder, exist_ok=True)
    run_benchmark(folder, args.repetitions, config["fio_file"])

if __name__ == "__main__":
    main()

