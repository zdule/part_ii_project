#!/bin/bash
make clean
rsync -avhe ssh . kamprobes_vm:test_victim
ssh kamprobes_vm test_victim/run.sh
