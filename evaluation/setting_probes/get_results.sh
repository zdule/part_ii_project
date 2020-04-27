#!/usr/bin/env bash
echo $1 $2 $3 $4
scp $1:~/part_ii_project/measurements/$2/$4 measurements/$3/$4
#scp $1:~/part_ii_project/evaluation/setting_probes/results/latest.csv downloaded_results.csv
