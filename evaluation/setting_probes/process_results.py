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
    for mechanism in df['mechanism'].unique():
        df_mech = df[df['mechanism'] == mechanism].groupby('n_probes', sort=True)
        means = df_mech.mean().reset_index()
#means['time'] = means['set_time']+means['release_time']
        print(means)
        plt.plot('n_probes','set_time', data = means, label=mechanism + " set")
        plt.plot('n_probes','release_time', data = means, label=mechanism + " release")
    plt.legend()
    plt.savefig(output)
    plt.show()

if __name__== "__main__":
    path = Path(sys.argv[1])
    logs = process_logs(path/"results.csv", path/"setting_probes.png")

