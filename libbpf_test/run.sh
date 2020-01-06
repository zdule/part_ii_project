#!/bin/bash
cd Desktop/libbpf_test || exit 1
make clean || exit 1
make || exit 1
sudo ./build/test_user
