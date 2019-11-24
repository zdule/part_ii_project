#!/bin/sh

# remove old device files
rm /dev/kambpf_list
rm /dev/kambpf_update

# unload old version of the module
rmmod kambpf

insmod ./build/kambpf.ko || exit 1

major=`cat /proc/devices | grep kambpf | cut -d ' ' -f 1`

mknod /dev/kambpf_list c $major 0
mknod /dev/kambpf_update c $major 1
