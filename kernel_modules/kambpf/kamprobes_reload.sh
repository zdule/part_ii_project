#!/bin/sh

# unload old version of the module
rmmod kamprobes
insmod ~/kamprobes/build/kamprobes.ko || exit 1

