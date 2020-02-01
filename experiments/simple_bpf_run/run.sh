#!/bin/bash
cd Desktop/simple_ebpf_run || exit 1
make clean || exit 1
make || exit 1
cd build
sudo rmmod simple_ebpf_run  
sudo insmod simple_ebpf_run.ko || exit 1
cd ..
sudo python ./simple_bcc.py || exit 1
sudo -S rmmod simple_ebpf_run  
dmesg | tail 
