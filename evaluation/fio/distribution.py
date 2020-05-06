from fio_helper import run_traced_fio
from pathlib import Path
import argparse
from os import makedirs, getenv, umask

DEFAULT_PATH = str(Path(getenv("project_dir")) / "measurements/default")

def distribution(output_folder):
    for mechanism in ['kambpfprobes','noprobes','kprobes']:
        log_path = output_folder / f"mechanism-{mechanism}.json" 
        run_traced_fio(mechanism, 'latency_log.fio', log_path, log_type='json', latency_log=True)

def main():
    umask(0)

    parser = argparse.ArgumentParser(description='Run the low load latency benchmark with different number of dummy probes')
    parser.add_argument('-o', type=str, default=DEFAULT_PATH,
            help='Folder in which to store log results')
    args = parser.parse_args()

    folder = Path(args.o) / "distribution"
    makedirs(folder, exist_ok=True)
    distribution(folder)

if __name__ == "__main__":
    main()

