#!/bin/bash
scp * kamprobes_vm:Desktop/simple_ebpf_run/
ssh kamprobes_vm ./Desktop/simple_ebpf_run/run.sh
