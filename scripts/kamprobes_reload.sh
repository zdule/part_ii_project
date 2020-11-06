#!/bin/bash

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

set -e
parent_dir=$(dirname $BASH_SOURCE[0]) 
echo $parent_dir
source $parent_dir/env.sh
source $scripts/common.sh

unload() {
    # unload old version of the module
    if is_loaded kamprobes; then
        rmmod kamprobes
    fi
}

load() {
	if ! is_loaded kamprobes; then
		insmod $project_dir/kernel_modules/kamprobes/build/kamprobes.ko
	fi
}

# Call the functions passed in as the first argument
$1
