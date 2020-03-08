#!/bin/bash

set -e
parent_dir=$(dirname $BASH_SOURCE[0]) 
source $parent_dir/env.sh
source $scripts/common.sh

unload() { 
	ensure_file_deleted /dev/test_victim
    if is_loaded test_victim_main; then
        rmmod test_victim_main
    fi
}

load() {
    if ! is_loaded test_victim_main; then
        insmod $project_dir/kernel_modules/test_victim/build/test_victim_main.ko
    fi
	major=`cat /proc/devices | grep -w test_victim | cut -d ' ' -f 1`
    ensure_file_deleted /dev/test_victim
	mknod /dev/test_victim c $major 0 || exit 1
}

# call the function passed in as the first argument
$1

