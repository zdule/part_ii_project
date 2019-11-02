#!/bin/bash
cd Desktop/simple_ebpf_run || exit 1
make clean || exit 1
make || exit 1
sudo -S su  < .env || exit 1
sudo -S rmmod simple_ebpf_run  
sudo insmod simple_ebpf_run.ko || exit 1
sudo python ./simple_bcc.py
sudo -S rmmod simple_ebpf_run  
