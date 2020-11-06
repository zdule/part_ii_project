#!/usr/bin/env python3

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

import sys
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def process_logs(path, output, ignore_kprobes=False):
    df = pd.read_csv(path)
    print(df)
    df['n_probes'] = df['n_probes'].astype(int)
    df['set_time'] = df['set_time'].astype(float)
    df['release_time'] = df['release_time'].astype(float)
    for mechanism in ["kambpfprobes","kprobes"]: #df['mechanism'].unique():
        if ignore_kprobes and mechanism == "kprobes":
            continue
        df_mech = df[df['mechanism'] == mechanism].groupby('n_probes', sort=True)
        means = df_mech.mean().reset_index()
        std = df_mech.std().reset_index()
        mx = df_mech.max().reset_index()
        mn = df_mech.min().reset_index()
        print(means)
        plt.plot('n_probes','set_time', data = means, label=mechanism + " set")
        plt.fill_between(means['n_probes'], mx['set_time'], mn['set_time'], alpha=0.2)
        plt.plot('n_probes','release_time', data = means, label=mechanism + " release")
        plt.fill_between(means['n_probes'], mx['release_time'], mn['release_time'], alpha=0.2)

    plt.ylabel("Time [s]")
    plt.xlabel("Number of probes")

    plt.legend()
    plt.savefig(output)
    plt.show()

if __name__== "__main__":
    path = Path(sys.argv[1])
    logs = process_logs(path/"results.csv", path/"setting_probes.png")
    logs = process_logs(path/"results.csv", path/"setting_probes_kambpf_only.png", True)

