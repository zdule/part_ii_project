#!/bin/bash
cd ~/kambpf || exit 1
make clean || exit 1
make || exit 1
sudo ./kambpf_reload.sh
