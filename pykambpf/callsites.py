#!/usr/bin/env python3

import argparse

from elftools.elf.elffile import ELFFile
from capstone import *

import os
import shutil
from pathlib import Path
from subprocess import run

def is_in_section(addr, ndx, section, elf_file):
    if ndx == 'ABS':
        raise ValueError("Not supported")
        return addr >= section['sh_addr'] and addr < section['sh_addr'] + section['sh_size']
    else:
        return elf_file.get_section(ndx)['sh_name'] == section['sh_name']

def parse_module_ko(module_path):
    call_graph = dict()
    with open(module_path, 'rb') as f:
        elf_file = ELFFile(f)
        code = elf_file.get_section_by_name('.text')
        symtab = elf_file.get_section_by_name('.symtab')
        relocs = elf_file.get_section_by_name('.rela.text')
        
        relmap = dict()
        for relocation in relocs.iter_relocations():
            symbol = symtab.get_symbol(relocation['r_info_sym'])
            relmap[relocation['r_offset']] = symbol.name

        code_instructions = code.data()
        for symbol in symtab.iter_symbols():
            if symbol['st_info']['type'] == "STT_FUNC":
                if not is_in_section(symbol['st_value'], symbol['st_shndx'], code, elf_file):
                    continue
                md = Cs(CS_ARCH_X86, CS_MODE_64)

                start = symbol['st_value']
                end = start + symbol['st_size']
                for i in md.disasm(code_instructions[start:end], offset=0):
                    if i.mnemonic=="call":
                        if (i.address+1 + start) in relmap:
                            target = relmap[i.address+1 + start]
                            if symbol.name not in call_graph:
                                call_graph[symbol.name] = []
                            call_graph[symbol.name].append((i.address, target, 0))
                        else:
                            print("WARNING MISSING SOME CALLSITES")
                            print("call site not in relocation table")
        return call_graph

def get_elf_details(vmlinux_path, calls_path):
    with open(calls_path, 'w') as out:
        with open(vmlinux_path, 'rb') as f:
            elf_file = ELFFile(f)

            # Disassemble code for searching callsites
            code = elf_file.get_section_by_name('.text')
            addr = code['sh_addr']
            ops = code.data()
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.skipdata = True
            for i in md.disasm(ops, addr):
                if i.mnemonic=="call":
                    arg = ""
                    if i.op_str.startswith('[0x') and i.op_str.endswith(']'):
                        arg = i.op_str[1:-1]
                    elif i.op_str.startswith('0x'):
                        arg = i.op_str
                    if arg != '':
                        print(f'0x{i.address:x} {arg}', file=out)


def init_cache(cache_path):
    uname = os.uname().release
    if isinstance(cache_path, str):
        cache_path = Path(cache_path)
    cache_path.mkdir(parents=True, exist_ok=True)

    calls_path = cache_path / f'calls-{uname}' 
    vmlinuz_source = f'/boot/vmlinuz-{uname}'
    vmlinux_path = cache_path / f'vmlinux-{uname}'
    system_map_path = cache_path / f'System.map-{uname}'
    system_map_source = f'/boot/System.map-{uname}'

    if not calls_path.is_file():
        if not vmlinux_path.is_file():
            extract_vmlinux_prog = f"/usr/src/linux-headers-{uname}/scripts/extract-vmlinux"
            run([extract_vmlinux_prog, vmlinuz_source], stdout=open(vmlinux_path,'wb'))
        get_elf_details(vmlinux_path, calls_path)

    if not system_map_path.is_file():
        shutil.copyfile(system_map_source, system_map_path)
    
    return (calls_path, system_map_path)

def main():
    parse_module_ko("cache/kambpf.ko")

if __name__ == '__main__':
    main()

