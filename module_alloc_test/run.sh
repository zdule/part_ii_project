#!/bin/bash
cd module_alloc_test || exit 1
make clean || exit 1
make || exit 1
sudo -S su  < .env || exit 1
sudo -S rmmod module_alloc_test  
sudo insmod module_alloc_test.ko || exit 1
sudo -S rmmod module_alloc_test  
dmesg
