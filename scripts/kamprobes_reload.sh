#!/bin/bash

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
