import sys
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path
from process_logs import process_logs


def fix_types(results):
    results['nprobes'] = results['nprobes'].astype(int)
    return results

def plot_bandwidth(results, output_path):
    mechanisms = results['mechanism'].unique()
    for mech in mechanisms:
        groupby = results[results['mechanism'] == mech].groupby('nprobes', sort=True)
        means = groupby.mean().reset_index()
        std = groupby.std().reset_index()
        mx = groupby.max().reset_index()
        mn = groupby.min().reset_index()

        plt.plot('nprobes','rbw', data=means, label=mech)
#plt.errorbar(means['nprobes'], means['rlat'], yerr=std['rlat'], label=mech);
        plt.fill_between(means['nprobes'], means['rbw'] - std['rbw'],means['rbw'] + std['rbw'], alpha=0.2)
#plt.fill_between(means['nprobes'], mn['rlat'], mx['rlat'], alpha=0.2)
     
    plt.ylabel("Bandwidth [KiB/s]")
    plt.xlabel("Number of auxiliary probes")

    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)

def plot(results, output_path):
    mechanisms = results['mechanism'].unique()
    results['rlat'] /= 1000
    results['rlatstd'] /= 1000
    for mech in mechanisms:
        groupby = results[results['mechanism'] == mech].groupby('nprobes', sort=True)
        means = groupby.mean().reset_index()
        std = groupby.std().reset_index()
        mx = groupby.max().reset_index()
        mn = groupby.min().reset_index()

        plt.plot('nprobes','rlat', data=means, label=mech)
        plt.fill_between(means['nprobes'], means['rlat'] - std['rlat'],means['rlat'] + std['rlat'], alpha=0.2)
     
    plt.ylabel("Average read latency [μs]")
    plt.xlabel("Number of auxiliary probes")


    plt.legend()
    plt.tight_layout()
    plt.savefig(output_path)

if __name__== "__main__":
    logs = process_logs(Path(sys.argv[1]))
    logs = fix_types(logs)
    if "latency" in sys.argv[1]:
        plot(logs, Path(sys.argv[1])/"average_latency.png")
    if "bandwidth" in sys.argv[1]:
        plot_bandwidth(logs, Path(sys.argv[1])/"average_bandwidth.png")
