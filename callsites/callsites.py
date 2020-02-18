#!/usr/bin/env python3

import argparse

from elftools.elf.elffile import ELFFile
from capstone import *

import os
import shutil
from pathlib import Path
from subprocess import run

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
	# awful code, if we're not running under sudo then this makes no sense
	# and if we are then we don't care about files being saved as root
	"""
	suid = os.geteuid()
	sgid = os.getegid()
	ruid = int(os.environ['SUDO_UID'])
	rgid = int(os.environ['SUDO_GID'])
	os.setegid(rgid)
	os.seteuid(ruid)
	"""

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
#vmlinux_path.touch()
#os.seteuid(suid)
			extract_vmlinux_prog = f"/usr/src/linux-headers-{uname}/scripts/extract-vmlinux"
			run([extract_vmlinux_prog, vmlinuz_source], stdout=open(vmlinux_path,'wb'))
#os.seteuid(ruid)
		get_elf_details(vmlinux_path, calls_path) 		
		
	if not system_map_path.is_file():
		system_map_path.touch()
#os.seteuid(suid)
		shutil.copyfile(system_map_source, system_map_path)
#os.seteuid(ruid)
	
#	os.seteuid(suid)	
#os.setegid(sgid)
	return (calls_path, system_map_path)

def main():
	init_cache('cache')
	exit(0)
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

	get_elf_details(args.vmlinux_path, 'calls')


if __name__ == '__main__':
	main()

