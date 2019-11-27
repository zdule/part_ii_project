#!/bin/bash
cd ~/kambpf || exit 1
make clean || exit 1
make || exit 1
sudo ./kambpf_reload.sh
#sudo ./build/user_main
sudo python simple_bcc.py
