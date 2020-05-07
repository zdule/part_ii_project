#!/bin/bash

set -e
parent_dir=$(dirname $BASH_SOURCE[0]) 
source $parent_dir/env.sh
source $scripts/common.sh

unload() { 
	ensure_file_deleted /dev/test_module
    if is_loaded test_module_main; then
        rmmod test_module_main
    fi
}

load() {
    if ! is_loaded test_module_main; then
        insmod $project_dir/kernel_modules/test_module/build/test_module_main.ko
    fi
	major=`cat /proc/devices | grep -w test_module | cut -d ' ' -f 1`
    ensure_file_deleted /dev/test_module
	mknod /dev/test_module c $major 0 || exit 1
}

# call the function passed in as the first argument
$1

