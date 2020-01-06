#!/bin/bash
scp * kamprobes_vm:Desktop/libbpf_test/
ssh kamprobes_vm ./Desktop/libbpf_test/run.sh
