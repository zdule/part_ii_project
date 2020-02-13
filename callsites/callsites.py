#!/usr/bin/env python3

import argparse

import json
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection
from capstone import *

def get_elf_details(vmlinux_path):
    syms = {}
    with open('calls', 'w') as out:
        with open(vmlinux_path, 'rb') as f:
            elf_file = ELFFile(f)

            # Disassemble code for searching callsites
            code = elf_file.get_section_by_name('.text')
            addr = code['sh_addr']
            ops = code.data()
            md = Cs(CS_ARCH_X86, CS_MODE_64)
            md.skipdata = True
            print(code['sh_addr'])
            for i in md.disasm(ops, addr):
                if i.mnemonic=="call":
                    arg = ""
                    if i.op_str.startswith('[0x') and i.op_str.endswith(']'):
                        arg = i.op_str[1:-1]
                    elif i.op_str.startswith('0x'):
                        arg = i.op_str
                    if arg != '':
                        print(f'0x{i.address:x} {arg}', file=out)

    return syms


def main():
    """
    Main.
    """
    global args
    global p_addr_delta
    global stage
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest="vmlinux_path", action='store', required=True,
                        help="""Path to vmlinux. (Typically /usr/src/linux/vmlinux but varies according to distribution and installed kernel. If you build your own kernel you'll find it in the build dir)""")

    args = parser.parse_args()

    syms = get_elf_details(args.vmlinux_path)


if __name__ == '__main__':
    main()
