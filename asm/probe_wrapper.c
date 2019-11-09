// #include "probe_wrapper.h"
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>

static char *template_buffer = "\x48\xc7\x04\x24\x00\x00\x00\x00\xe9\x00\x00\x00\x00\x68\x00\x00\x00\x00\x75\x08\x48\xc7\x04\x24\x00\x00\x00\x00\xe9\x00\x00\x00\x00\x68\x00\x00\x00\x00\xe9\x00\x00\x00\x00";
const size_t probe_wrapper_buffer_length = 43;

static bool signextends(u64 x) {
    return ((x & 0xFFFFFFFF80000000) == 0xFFFFFFFF80000000) || ((x & 0xFFFFFFFF80000000) == 0);
}

static bool R_X86_64_PC32(void *buffer, u64 load_address, u64 offset, u64 symbol_offset, u64 addend) {
    u64 result = symbol_offset - (load_address + offset) + addend;
    if (!signextends(result))
        return true;
    u32 *to_relocate = (u32  *) (buffer+offset);
    *to_relocate = result & 0x00000000FFFFFFFF;
    return false; 
}

static bool R_X86_64_32S(void *buffer, u64 load_address, u64 offset, u64 symbol_offset, u64 addend) {
    u64 result = symbol_offset + addend;
    if (!signextends(result))
        return true;
    u32 *to_relocate = (u32  *) (buffer+offset);
    *to_relocate = result & 0x00000000FFFFFFFF;
    return false; 
}

bool probe_wrapper_load_code(void *buffer, u64 load_address,
    u64 probed_function,u64 return_address,u64 entry_handler,u64 ret_handler,u64 *start
) {

    memcpy(buffer, template_buffer, probe_wrapper_buffer_length);
    bool failed =  
    R_X86_64_32S(buffer,load_address,0x000000000004,load_address,+0xd) ||
    R_X86_64_32S(buffer,load_address,0x00000000000e,return_address,+0x0) ||
    R_X86_64_32S(buffer,load_address,0x000000000018,load_address,+0x21) ||
    R_X86_64_32S(buffer,load_address,0x000000000022,return_address,+0x0) ||
    R_X86_64_PC32(buffer,load_address,0x000000000009,entry_handler,-0x4) ||
    R_X86_64_PC32(buffer,load_address,0x00000000001d,probed_function,-0x4) ||
    R_X86_64_PC32(buffer,load_address,0x000000000027,ret_handler,-0x4);
    return failed;
}
