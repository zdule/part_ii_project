import json
from glob import glob
import pandas as pd

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

def process_logs(folder, file_prefix = ""):
    logs = glob(str(folder / (file_prefix+"*.json")))

    df = None
    for log in logs:
        newdf = process_log(log)
        if df is None:
            df = newdf
        else:
            df = df.append(newdf)
    print(df)
    return df
