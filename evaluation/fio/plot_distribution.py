import pandas as pd
import sys
import matplotlib.pyplot as plt
from pathlib import Path
import seaborn as sb
import numpy as np

from process_logs import process_logs



def plot_bandwidth(results, output_path):
    results['rbw'] /= 1024
    results['wbw'] /= 1024
    ylabels = ["Read throughput [MiB/s]", "Write throughput [MiB/s]"]
    fig, axes = plt.subplots(1,2, sharey=True, figsize=(8,4))
    for i, rw in enumerate(['rbw','wbw']):
        sb.boxplot(x="mechanism", y=rw, data=results, showfliers = False, ax=axes[i])
        sb.swarmplot(x="mechanism", y=rw, data=results, color=".25", ax=axes[i])
        axes[i].set_ylabel(ylabels[i])
        axes[i].set_xlabel("")
    plt.savefig(str(output_path / "bandwidth.png"))
    plt.show()

def plot(res, output_path):
    fig, axes = plt.subplots(3,2, sharex='col', figsize=(8,4))
    res['latency'] /= 1000
    ranges = [(200,600), (100,400)]
    xlabels = ["Read latency [μs]", "Write latency [μs]"]
    for j,rw in enumerate(['read','write']):
        reads = res[res['rw']==rw]
        pacici = []
        labels = []
        data = reads.groupby('mechanism')['latency'].apply(list)
        prop_cycle = plt.rcParams['axes.prop_cycle']()
        for i,(k,v) in enumerate(data.items()):
            _,_,pache = axes[i][j].hist(v, 35, label=k, range = ranges[j], **next(prop_cycle))
            pacici.append(pache[0])
            labels.append(k)
        axes[len(data)-1][j].set_xlabel(xlabels[j])

    plt.figlegend(pacici,labels, loc = 'upper center', ncol=3 )
    fig.text(0.04, 0.5, 'Frequency', va='center', rotation='vertical')
    plt.savefig(str(output_path / "distribution.png"))
    plt.show()

def log_plot(res, output_path):
    fig, axes = plt.subplots(1,2, sharey=True, figsize=(8,4))
    res['latency'] /= 1000
    ylabels = {'read' : 'Read', 'write' : 'Write'}
    for j, rw in enumerate(['read','write']):
        reads = res[res['rw']==rw]
        pacici = []
        labels = []
        data = reads.groupby('mechanism')['latency'].apply(list)
        for i,(k,v) in enumerate(data.items()):
            v = sorted(v)[:-10]
            x = np.linspace(0,100, num=len(v))
            axes[j].plot(x, v, label=k)
            axes[j].set_xlabel("Percentile")
            axes[j].set_ylabel(f'{ylabels[rw]} latency [μs]')

    plt.legend()
    plt.tight_layout()
    plt.savefig(str(output_path / "percentiles.png"))
    plt.show()

def process_lat_logs(folder):
    res = None
    for mechanism in ['kambpfprobes', 'kprobes', 'noprobes']:
        path = folder / f"latency_mechanism-{mechanism}.json_lat.log"
        df = pd.read_csv(path, header=None)
        df = df[[1,2]].rename(columns={1: "latency", 2: "rw"})
        df.loc[df['rw']==0,'rw'] = 'read'
        df.loc[df['rw']==1,'rw'] = 'write'
        mechanism_map = {'kambpfprobes':'kambpfprobes', 'kprobes' : 'kprobes', 'noprobes': 'untraced'}
        df['mechanism'] = mechanism_map[mechanism]
        print(df)
        if res is None:
            res = df
        else:
            res = res.append(df)
    return res

if __name__== "__main__":
    path = Path(sys.argv[1])
    lat_logs = process_lat_logs(path)
    logs = process_logs(path, "bandwidth")
    logs.loc[logs['mechanism'] == 'noprobes','mechanism'] = 'untraced'
    plot_bandwidth(logs, path)
    plot(lat_logs, path)
    log_plot(lat_logs, path)
