#!/bin/bash
cd Desktop/simple_ebpf_run || exit 1
make clean || exit 1
make || exit 1
cd build
sudo -S su  < .env || exit 1
sudo bash << 'EOF123'
rmmod simple_ebpf_run  
whoami
insmod simple_ebpf_run.ko || exit 1
cd ..
python ./simple_bcc.py || exit 1
addr=`cat /sys/module/simple_ebpf_run/parameters/test_address`
echo $addr
echo $addr > /sys/module/simple_ebpf_run/parameters/addr
echo "" > /sys/module/simple_ebpf_run/parameters/trigger
# sudo -S rmmod simple_ebpf_run  
EOF123
dmesg
