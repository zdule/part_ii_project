#!/bin/bash
unload() { 
	rm /dev/test_victim || true
	rmmod test_victim_main || true
}

load() {
	insmod build/test_victim_main.ko || exit 1
	major=`cat /proc/devices | grep test_victim | cut -d ' ' -f 1`
	mknod /dev/test_victim c $major 0 || exit 1
}

# call the function passed in as the first argument
$1

