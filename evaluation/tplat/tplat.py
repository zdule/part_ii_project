#!/usr/bin/env python3
from subprocess import Popen, PIPE, run
import subprocess
from pathlib import Path
from os import makedirs, environ
import argparse
import datetime
JOB_FILE_NAME = "tplat.fio"

def run_experiment(output_path, num_jobs):
    env = environ.copy()
    env['NUMJOBS'] = str(num_jobs)
    fio = run(['fio', JOB_FILE_NAME, '--output', output_path, '--output-format', 'json'], env=env)

def run_for_jobs(output_folder):
    for i in range(10,201,10):
        filename = output_folder / f"log_{i}.json"
        run_experiment(filename, i)

def main():
    parser = argparse.ArgumentParser(description='Benchmark latency and bandwidth with different loads.')
    parser.add_argument('-o', type=str, default='measurements/',
            help='Folder in which to store log results')
    args = parser.parse_args()

    folder = Path(args.o)
    makedirs(folder, exist_ok=True)
    run_for_jobs(folder)

main()
