#!/bin/bash

set -e
parent_dir=$(dirname $BASH_SOURCE[0]) 
source $parent_dir/../../scripts/env.sh
env
sudo --preserve-env=PYTHONPATH,kambpf_reload,kamprobes_reload,project_dir LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./setting_probes_benchmark.py
