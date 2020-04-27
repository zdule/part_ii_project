import os
import re
import sys
import json
import statistics as stat
import pandas as pd
import matplotlib.pyplot as plt
from glob import glob
from pathlib import Path

def process_log(path):
    log = json.load(open(path,'r')) 
    log = log['jobs'][0]

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

    p = pd.DataFrame([res.values()], columns=res.keys())
  
    filename =  path.split("/")[-1].split(".")[0] 
    components = filename.split("_")
    for s in components:
        kvpair = s.split('-')
        if len(kvpair) != 2:
            continue
        p[kvpair[0]] = kvpair[1]
    return p

def process_logs(folder):
    logs = glob(str(folder / "*.json"))

    df = None
    for log in logs:
        newdf = process_log(log)
        if df is None:
            df = newdf
        else:
            df = df.append(newdf)
    print(df)
    return df

def fix_types(results):
    results['nprobes'] = results['nprobes'].astype(int)
    return results

def plot(results, output_path):
    mechanisms = results['mechanism'].unique()
    results['rlat'] /= 1000
    results['rlatstd'] /= 1000
    for mech in mechanisms:
        groupby = results[results['mechanism'] == mech].groupby('nprobes', sort=True)
        means = groupby.mean().reset_index()
        std = groupby.std().reset_index()

        plt.plot('nprobes','rlat', data=means, label=mech)
#plt.errorbar(means['nprobes'], means['rlat'], yerr=std['rlat'], label=mech);
        plt.fill_between(means['nprobes'], means['rlat'] - std['rlat'],means['rlat'] + std['rlat'], alpha=0.2)
     
    plt.title("Read latency at low utilisation \n changing with the number of auxiliary probes")
    plt.ylabel("Average read latency [μs]")
    plt.xlabel("Number of auxiliary probes")

    plt.xticks(results['nprobes'].unique())

    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)

if __name__== "__main__":
    logs = process_logs(Path(sys.argv[1]))
    logs = fix_types(logs)
    plot(logs, Path(sys.argv[1])/"average_latency.png")
