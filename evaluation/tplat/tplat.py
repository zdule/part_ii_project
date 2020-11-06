#!/usr/bin/env python3

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

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
