#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

from bisect import bisect

from . import  callsites
from pathlib import Path
CALLS_PATH, SYMBOLS_PATH = callsites.init_cache(Path.home()/ ".cache/pykambpf/")

KALLSYMS_PATH = '/proc/kallsyms'

def reverse_dict(d):
    return {v: k for k, v in d.items()}

regs = ['ax','bx','cx','dx','si','di','bp','r8','r9','r10','r11','r12','r13','r14','r15']
regs_long = [reg if reg.startswith('r') else 'r'+reg for reg in regs]

class CallGraph:
    def _read_kallsyms(kallsyms_path):
        kallsyms = {}
        with open(kallsyms_path, 'r') as kf:
            for l in kf.readlines():
                tok = l.split()
                # W is for weak symbols (lower priory when linking with other symbols with same name
                # see man nm
                # memcpy is a weak symbol
                if tok[1] in ['t','T', 'W']:
                    kallsyms[tok[2]] = int(tok[0],16)
        return kallsyms

    def _read_calls(calls_path):
        calls = []
        with open(calls_path, 'r') as cf:
            for l in cf.readlines():
                tok = l.split()
                addr = int(tok[0],16)
                target = int(tok[1],16)
                calls.append((addr,target))
        return calls

    def _read_symbols(symbols_path):
        symbols = []
        with open(symbols_path, 'r') as sf:
            for l in sf.readlines():
                tok = l.split()
                if tok[1] in ['t','T']:
                    symbols.append((int(tok[0],16),tok[2]))
        return symbols

    def l_addr_to_fun(self, l_addr):
        return self.reverse_kallsyms(l_addr)

    # f_ means in the ELF file, l_ means when loaded 
    def _f_addr_to_fun_and_l_addr(self, f_addr):
        fun_id = bisect(self.symbols,(f_addr,'ħ'))-1
        f_fun_addr, fun_name = self.symbols[fun_id]
        l_fun_addr = self.kallsyms[fun_name]
        return (fun_name,f_addr-f_fun_addr+l_fun_addr)

    def _graph_add_callsite(self, site_fun, site_addr, target_addr, target_fun):
        if site_fun not in self.graph:
            self.graph[site_fun] = []
        self.graph[site_fun].append((site_addr, target_addr, target_fun))

    def _populate_graph(self, calls):
        self.graph = {}
        for (call_site, call_target) in calls:
            site_fun, l_site_addr = self._f_addr_to_fun_and_l_addr(call_site)
            target_fun, l_target_addr = self._f_addr_to_fun_and_l_addr(call_target)
            self._graph_add_callsite(site_fun, l_site_addr, l_target_addr, target_fun)
            

    def parse_module(self, module_ko_path):
        module_calls = callsites.parse_module_ko(module_ko_path)
        for site_fun, calls in module_calls.items():
            for (site_off, target_fun, target_off) in calls:
                site_addr = self.kallsyms[site_fun] + site_off
                target_addr = self.kallsyms[target_fun] + target_off
                self._graph_add_callsite(site_fun, site_addr, target_addr, target_fun)

    def __init__(self, calls_path=CALLS_PATH, kallsyms_path=KALLSYMS_PATH, symbols_path=SYMBOLS_PATH):
        self.kallsyms = CallGraph._read_kallsyms(kallsyms_path)
        self.reverse_kallsyms = reverse_dict(self.kallsyms)
        self.symbols = CallGraph._read_symbols(symbols_path)
        calls = CallGraph._read_calls(calls_path)
        self._populate_graph(calls)
        
        self.thunks = {}
        for i, reg in enumerate(regs):
            self.thunks[self.kallsyms["__x86_indirect_thunk_"+regs_long[i]]] = reg

    def calls_from_fun(self, fun):
        if isinstance(fun, int):
            return self.graph[self.reverse_kallsyms[fun]]
        return self.graph[fun]

    def get_edges_sites(self, fun, target):
        calls = self.graph[fun]
        return list(map(lambda t: t[0], filter(lambda t: t[2] == target, calls)))

    def indirect_calls_from_fun(self, fun):
        calls = self.graph[fun]
        result = []
        for (site, target, fun) in calls: 
            if target in self.thunks:
                result.append((site,self.thunks[target]))
        return result
