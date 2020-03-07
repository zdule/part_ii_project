#!/bin/bash
make clean
scp -r $(pwd)/** kamprobes_vm:kambpf
ssh kamprobes_vm kambpf/run.sh
