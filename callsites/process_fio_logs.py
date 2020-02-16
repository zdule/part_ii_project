import os
import re
import sys
import json
import statistics as stat

def process_log(path):
    log = json.load(open(path,'r')) 
    log = log['jobs'][0]

    res = dict()
    res['read_lat'] = log['read']['lat_ns']['mean']
    res['write_lat'] = log['write']['lat_ns']['mean']
    res['read_bw'] = log['read']['bw']
    res['write_bw'] = log['write']['bw']
    res['error'] = log['error']
    return res

def process_logs(folder):
    pattern = re.compile(r'([^\-]+)-([^.]+)\.json')

    logs = []
    with os.scandir(folder) as it:
        for entry in it:
            if entry.is_file() and pattern.fullmatch(entry.name):
                name,seq = pattern.fullmatch(entry.name).group(1,2) 
                logs.append(((name,seq),process_log(entry.path)))

    res = dict()
    value_fields = ['read_lat', 'write_lat', 'read_bw', 'write_bw']
    fields = value_fields + ['error']
    for ((name,seq),log) in logs:
        if name not in res:
            res[name] = { f+'s' : [] for f in fields }
        nres = res[name]
        for field in fields:
            nres[field+'s'].append(log[field])
    for v in res.values():
        for f in value_fields:
            v[f+'_mean'] =  stat.mean(v[f+'s'])
            v[f+'_stdev'] =  stat.stdev(v[f+'s'])
    return res

if __name__== "__main__":
    print(json.dumps(process_logs(sys.argv[1]), sort_keys=True, indent=4))
