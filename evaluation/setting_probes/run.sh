#!/bin/bash

sudo --preserve-env=PYTHONPATH,kambpf_reload,kamprobes_reload LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./setting_probes_benchmark.py
