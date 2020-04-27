#!/usr/bin/env bash

mkdir -p measurements/$3/
scp -r $1:~/part_ii_project/measurements/$2/$4/ measurements/$3/
