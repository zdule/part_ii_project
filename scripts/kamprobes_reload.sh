#!/bin/sh

source scripts/common.sh

unload() {
    # unload old version of the module
    if is_loaded kamprobes; then
        rmmod kamprobes
    fi
}

load() {
    insmod kernel_modules/kamprobes/build/kamprobes.ko || exit 1
}

