#!/usr/bin/env python3

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

import os
import re
import sys
import json
from glob import glob
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

def process_job(log):
    res = dict()
    res['rlat'] = float(log['read']['lat_ns']['mean'])
    res['wlat'] = float(log['write']['lat_ns']['mean'])
    res['rlatstd'] = float(log['read']['lat_ns']['stddev'])
    res['wlatstd'] = float(log['write']['lat_ns']['stddev'])
    res['rlatmax'] = float(log['read']['lat_ns']['max'])
    res['wlatmax'] = float(log['write']['lat_ns']['max'])
    res['rlat99'] = float(log['read']['clat_ns']['percentile']['99.000000'])
    res['wlat99'] = float(log['write']['clat_ns']['percentile']['99.000000'])
    res['rbw'] = float(log['read']['bw'])
    res['wbw'] = float(log['write']['bw'])
    res['rbwstd'] = float(log['read']['bw_dev'])
    res['wbwstd'] = float(log['write']['bw_dev'])
    res['error'] = int(log['error'])
    res['jobs'] = int(log['job options']['numjobs'])
    return res

def process_log(path):
    log = json.load(open(path,'r')) 
    load_log = log['jobs'][0]
    litmus_log = log['jobs'][1]

    load_res = process_job(load_log)
    litmus_res = process_job(litmus_log)

    abbr = dict()
    abbr['jobs'] = load_res['jobs']
    abbr['rlat'] = litmus_res['rlat']
    abbr['wlat'] = litmus_res['wlat']
    abbr['rlatstd'] = litmus_res['rlatstd']
    abbr['wlatstd'] = litmus_res['wlatstd']
    abbr['rlatmax'] = litmus_res['rlatmax']
    abbr['wlatmax'] = litmus_res['wlatmax']
    abbr['rlat99'] = litmus_res['rlat99']
    abbr['wlat99'] = litmus_res['wlat99']
    abbr['wbw'] = load_res['wbw']
    abbr['rbw'] = load_res['rbw']
    abbr['wbwstd'] = load_res['wbwstd']
    abbr['rbwstd'] = load_res['rbwstd']

    abbr['fakerlat'] = load_res['rlat']

    p = pd.DataFrame([abbr.values()], columns=abbr.keys())
    print(p)
    return p

def process_logs(folder):
    logs = glob(str(folder / "*.json"))
    print(logs)

    df = None
    for log in logs:
        newdf = process_log(log)
        if df is None:
            df = newdf
        else:
            df = df.append(newdf)
    df = df.sort_values(by='jobs')
    print(df)
    return df

def plot_tplat(results):
    fig, ax1 = plt.subplots()
    ax1.plot('jobs','rbw', data=results)
    ax2 = ax1.twinx() 
#ax2.plot('jobs','rlatmax', data=results)
#ax2.plot('jobs','rlat99', data=results)
    ax2.plot('jobs','rlat', data=results)
    ax2.plot('jobs','fakerlat', data=results)
    plt.show()
def get_probes(results):
    return set(results.index.get_level_values('probes'))

def plot_experiment(results):
    markers = ['o','v','s','h']
    for i,p in enumerate(get_probes(results)):
        pp = results.loc[p].reset_index()
        plt.plot('seq','read_lat', data=pp, marker=markers[i], linestyle='None')
    plt.show()

def plot_bar(results, field):
    means = results.groupby(level=0)[field].mean()
    errs = results.groupby(level=0)[field].std()
    print(errs)
    plt.bar(range(3),means, yerr=errs)
    plt.show()

if __name__== "__main__":
#process_log(sys.argv[1])
    logs = process_logs(Path(sys.argv[1]))
    plot_tplat(logs)
