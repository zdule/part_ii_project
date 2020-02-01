#!/bin/bash
scp * kamprobes_vm:module_alloc_test/
ssh kamprobes_vm ./module_alloc_test/run.sh
