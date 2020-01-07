#!/bin/bash
make clean
scp -r $(pwd)/** kamprobes_vm:test_victim
ssh kamprobes_vm test_victim/run.sh
