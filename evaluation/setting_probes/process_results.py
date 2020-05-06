#!/usr/bin/env python3

import sys
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def process_logs(path, output):
    df = pd.read_csv(path)
    print(df)
    df['n_probes'] = df['n_probes'].astype(int)
    df['set_time'] = df['set_time'].astype(float)
#df['release_time'] = df['release_time'].astype(float)
    for mechanism in ["kambpfprobes","kprobes"]: #df['mechanism'].unique():
#if mechanism == "kprobes":
#continue
        df_mech = df[df['mechanism'] == mechanism].groupby('n_probes', sort=True)
        means = df_mech.mean().reset_index()
        std = df_mech.std().reset_index()
        mx = df_mech.max().reset_index()
        mn = df_mech.min().reset_index()
#means['time'] = means['set_time']+means['release_time']
        print(means)
        plt.plot('n_probes','set_time', data = means, label=mechanism + " set")
#plt.fill_between(means['n_probes'], means['set_time'] - std['set_time'],means['set_time'] + std['set_time'], alpha=0.2)
        plt.fill_between(means['n_probes'], mx['set_time'], mn['set_time'], alpha=0.2)
#plt.errorbar(means['n_probes'], means['set_time'], yerr=[means['set_time']-mn['set_time'],mx['set_time']-means['set_time']], label=mechanism, capsize=5)
        plt.plot('n_probes','release_time', data = means, label=mechanism + " release")
        plt.fill_between(means['n_probes'], mx['release_time'], mn['release_time'], alpha=0.2)

#plt.ylim((0,1))
#plt.title("Time needed to insert / remove ")
    plt.ylabel("Time [s]")
    plt.xlabel("Number of probes")

#plt.xticks(df['n_probes'].unique())
    plt.legend()
#plt.tight_layout()
    plt.savefig(output)
    plt.show()

if __name__== "__main__":
    path = Path(sys.argv[1])
    logs = process_logs(path/"results.csv", path/"setting_probes.png")

