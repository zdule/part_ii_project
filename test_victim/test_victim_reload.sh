#!/bin/bash

rm /dev/test_victim

# unload old version of the module
rmmod test_victim

insmod ~/test_victim/build/test_victim.ko || exit 1

major=`cat /proc/devices | grep test_victim | cut -d ' ' -f 1`

mknod /dev/test_victim c $major 0
