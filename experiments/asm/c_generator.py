#! /usr/bin/env python3

import sys

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("source", help="filename of the assembly program, must end in .S")
parser.add_argument("-o", "--output", help="output filepath for the c source file")
args = parser.parse_args()

usage = "Usage: {} <asmfile.S>".format(sys.argv[0])

path = args.source
if path[-2:] != ".S":
    print("The source file name must end in '.S'");
    exit()
noext = path[:-2]

ofile = noext + ".o"
if not args.output:
    args.output = noext + ".c"
else: 
    if args.output.endswith(".c"):
        ofile = args.output[:-2] + ".o"
    else:
        ofile = args.output + ".o"

cfile = args.output
import os
basename = os.path.basename(args.output)

from subprocess import run, PIPE

func_args = []

def split_filter(l, sep):
    return list(filter(lambda l: l, l.split(sep)))

with open(path,'r') as sourcefile:
    lines = sourcefile.readlines()
    argslines = list(filter(lambda l : l.startswith("#ARGS:"), lines))
    if len(argslines) != 1:
        print("Exactly one line in the source file must start with #ARGS:")
        print("Lines that start with #ARGS: are :", argslines)
        exit()
    argsline = argslines[0][len("#ARGS:"):]
    args = argsline.split(",")
    for arg in args:
        tokens = arg.split(" ")
        tokens = list(filter(lambda l : l != "",tokens))
        if len(tokens) != 2 or tokens[0] not in ["in","out"]:
            print("Invalid format of arg \"{}\" in args line".format(arg))
            print("Example format of args line: #ARGS: in name1, in name2, out name3, out name4")
            exit()
        func_args.append(tokens) 


gcc_out = run(["gcc", "-c", path, "-o", ofile])

if gcc_out.returncode != 0:
    print("COMPILATION FAILED\n")
    exit(1)

hex_out = run(["readelf", "-x", ".text", ofile], encoding="utf-8", stdout=PIPE)


hex_bytes = ""
for l in hex_out.stdout.split('\n'):
    toks = split_filter(l," ")
    if (len(toks) and toks[0].startswith("0x")):
        toks = (toks[1:])[:-1]
        hex_bytes += "".join(toks)

syms_out = run(["readelf", "-s", ofile], encoding = "utf-8", stdout=PIPE)

output_values = {}
for l in syms_out.stdout.split('\n'):
    toks = split_filter(l," ")
    if len(toks) == 8 and toks[4] == "GLOBAL":
        value = toks[1]
        Ndx = toks[6] 
        name = toks[7]
        if Ndx == "UND":
            if not any(a[1] == name for a in func_args):
                print("ERROR undefined symbol {} not an input argument".format(name))
                exit(1)
        else:
           output_values[name] = value 

relocs_out = run(["readelf", "-r", ofile], encoding = "utf-8", stdout=PIPE)

relocs = []

for l in relocs_out.stdout.split('\n'):
    toks = split_filter(l," ")
    if len(toks) == 7 and toks[2].startswith("R_X86_64"):
        addend = toks[5] + '0x' + toks[6] 
        offset = '0x'+toks[0]
        relocs.append({'offset' : offset, 'typ' : toks[2], 'sym_name' : toks[4], 'addend': addend})

def escaped_hex(hx):
    assert(len(hx) % 2 == 0)
    res = ""
    for i in range(len(hx)//2):
        res += "\\x" + hx[2*i:2*i+2]
    return res


c_code = """\
// #include "{header}"
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

static char *template_buffer = "{program_code}";
const size_t {buffer_length_const} = {buffer_length};

static bool signextends(u64 x) {{
    return ((x & 0xFFFFFFFF80000000) == 0xFFFFFFFF80000000) || ((x & 0xFFFFFFFF80000000) == 0);
}}

static bool R_X86_64_PC32(void *buffer, u64 load_address, u64 offset, u64 symbol_offset, u64 addend) {{
    u64 result = symbol_offset - (load_address + offset) + addend;
    if (!signextends(result))
        return true;
    u32 *to_relocate = (u32  *) (buffer+offset);
    *to_relocate = result & 0x00000000FFFFFFFF;
    return false; 
}}

static bool R_X86_64_32S(void *buffer, u64 load_address, u64 offset, u64 symbol_offset, u64 addend) {{
    u64 result = symbol_offset + addend;
    if (!signextends(result))
        return true;
    u32 *to_relocate = (u32  *) (buffer+offset);
    *to_relocate = result & 0x00000000FFFFFFFF;
    return false; 
}}

bool {function_name}(void *buffer, u64 load_address,
    {other_arguments}) {{

    memcpy(buffer, template_buffer, {buffer_length_const});
    bool failed =  
    {relocations};
    return failed;
}}
"""
supported_reloc_types = {"R_X86_64_32S","R_X86_64_PC32"}
with open(cfile,'w') as generated:
    prefix = basename[:-2]
    header = prefix+".h"
    program_code = escaped_hex(hex_bytes) 
    buffer_length_const = prefix+"_buffer_length"
    buffer_length = len(hex_bytes) //2
    function_name = prefix + "_load_code"
    other_arguments = ",".join( "u64 "+name if typ == "in" else "u64 *"+name for (typ,name) in func_args)
    relocation_strs = []
    for r in relocs:
        if r['typ'] not in supported_reloc_types:
            print("Relocation type \"{}\", not supported. Use the readelf linux command\
                   to inspect relocations".format(r['typ']))
            exit(1)
        if r['sym_name'] == ".text":
            r['sym_name'] = "load_address"
        relocation_strs.append("{typ}(buffer,load_address,{offset},{sym_name},{addend})"\
                                .format(**r))
    relocations = " ||\n    ".join(relocation_strs)
    generated.write(c_code.format(header=header,
                    program_code=program_code, buffer_length_const=buffer_length_const,
                        buffer_length = buffer_length, function_name = function_name,
                        other_arguments = other_arguments, relocations = relocations))
