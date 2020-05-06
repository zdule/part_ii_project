import pandas as pd
import sys
import matplotlib.pyplot as plt
from pathlib import Path
import seaborn as sb
import numpy as np

def plot(res):
    for k,v in res.items():
        sb.distplot(v['reads'], hist=True,  
                     bins=1000, label=k)
    plt.legend()
    plt.show()

def log_plot(res):
    for k,v in res.items():
        ser = v['reads'].sort_values().reset_index()
        ser = ser[1].reset_index()
        print(len(ser))
        ser['plog'] = -np.log(1-ser['index']/len(ser))
        plt.plot(ser['plog'], ser[1], label = k)
#ser['a'] = ser['index']
        print(ser)
    plt.legend()
    plt.show()

def process_logs(folder):
    res = dict()
    for mechanism in ['kambpfprobes', 'kprobes', 'noprobes']:
        path = folder / f"mechanism-{mechanism}.json_lat.log"
        df = pd.read_csv(path, header=None)
        read_lats = df[df[2] == 0][1]
        write_lats = df[df[2] == 1][1]
        print(df)
        res[mechanism] = { "reads" : read_lats, "writes" : write_lats}
    return res

if __name__== "__main__":
    logs = process_logs(Path(sys.argv[1]))
    log_plot(logs)
