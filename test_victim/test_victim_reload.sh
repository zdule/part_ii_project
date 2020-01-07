#!/bin/bash

rm /dev/test_victim

# unload old version of the module
rmmod test_victim_main

insmod ~/test_victim/build/test_victim_main.ko || exit 1

major=`cat /proc/devices | grep test_victim | cut -d ' ' -f 1`

mknod /dev/test_victim c $major 0

./build/tests/entry_probe_correctness/userland build/tests/entry_probe_correctness/bpf.o
