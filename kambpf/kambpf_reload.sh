#!/bin/sh

unload() {
    rm /dev/kambpf_list
    rm /dev/kambpf_update
    rmmod kambpf || return 0
}

load() {
    insmod build/kambpf.ko

    major=`cat /proc/devices | grep kambpf | cut -d ' ' -f 1`

    mknod /dev/kambpf_list c $major 0 || exit 1
    mknod /dev/kambpf_update c $major 1 || exit 1
}

# run the function passed in as the first argument
$1
