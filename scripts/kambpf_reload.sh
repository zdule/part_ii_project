#!/bin/sh

source scripts/common.sh

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
        insmod kerenel_modules/kambpf/build/kambpf.ko
    fi

    ensure_files_deleted /dev/kambpf_list /dev/kambpf_update

    major=`cat /proc/devices | grep -w kambpf | cut -d ' ' -f 1`

    mknod /dev/kambpf_list c $major 0
    mknod /dev/kambpf_update c $major 1 || return 0
}

# run the function passed in as the first argument
$1
