#!/usr/bin/env python3

import sys
import pandas as pd
import matplotlib.pyplot as plt

def get_mechanisms(results):
    return set(results.index.get_level_values('mechanism'))

def process_logs(path):
    df = pd.read_csv(path)
    df = df.groupby(['mechanism','n_probes']).mean()
    for mechanism in get_mechanisms(df):
        df_mech = df.loc[mechanism].reset_index()
        n_probes = df_mech['n_probes']
        time = df_mech['time']
        plt.plot(n_probes,time)
    plt.show()

if __name__== "__main__":
    logs = process_logs(sys.argv[1])
