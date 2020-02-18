import os
import re
import sys
import json
import statistics as stat
import pandas as pd
import matplotlib.pyplot as plt

def process_log(path):
    log = json.load(open(path,'r')) 
    log = log['jobs'][0]

    res = dict()
    res['read_lat'] = float(log['read']['lat_ns']['mean'])
    res['write_lat'] = float(log['write']['lat_ns']['mean'])
    res['read_bw'] = float(log['read']['bw'])
    res['write_bw'] = float(log['write']['bw'])
    res['error'] = int(log['error'])
    return res

def process_logs(folder):
    pattern = re.compile(r'([^\-]+)-([^.]+)\.json')

    logs = pd.DataFrame(columns=['probes', 'seq','read_lat','write_lat','read_bw','write_bw','error'])
    with os.scandir(folder) as it:
        for entry in it:
            if entry.is_file() and pattern.fullmatch(entry.name):
                name,seq = pattern.fullmatch(entry.name).group(1,2) 
                l = process_log(entry.path)
                l['probes'] = name
                l['seq'] = int(seq)
                logs = logs.append(l,ignore_index=True)
    logs = logs.set_index(['probes','seq'])
    return logs

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
    logs = process_logs(sys.argv[1])
    plot_experiment(logs)
    plot_bar(logs,"write_lat")
