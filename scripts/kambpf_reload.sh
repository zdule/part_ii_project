#!/bin/bash

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

set -e
parent_dir=$(dirname $BASH_SOURCE[0]) 
source $parent_dir/env.sh

source $scripts/common.sh

# Unloads the kambpf module and removes its device files
unload() {
    ensure_files_deleted /dev/kambpf_list /dev/kambpf_update
    if is_loaded kambpf; then
        rmmod kambpf || return 0
    fi
}

# Makes sure that the kambpf module is loaded and that 
# its device files exist
load() {
    if ! is_loaded kambpf; then
        insmod $project_dir/kernel_modules/kambpf/build/kambpf.ko
    fi

    ensure_files_deleted /dev/kambpf_list /dev/kambpf_update

    major=`cat /proc/devices | grep -w kambpf | cut -d ' ' -f 1`

    mknod /dev/kambpf_list c $major 0
    mknod /dev/kambpf_update c $major 1 || return 0
}

# run the function passed in as the first argument
$1
