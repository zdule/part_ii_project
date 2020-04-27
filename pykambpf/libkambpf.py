import ctypes as ct

UPDATE_DEVICE_PATH = b"/dev/kambpf_update"
class KambpfListHeader(ct.Structure):
    _fields_ = [
        ("num_entries", ct.c_uint64),
        ("offset", ct.c_uint64),
        ("max_num_entries", ct.c_uint64),
        ("_pad",ct.c_uint64),
    ]

class KambpfListEntry(ct.Structure):
    _fields_ = [
        ("instruction_address", ct.c_uint64),
        ("data_p", ct.c_uint64),
        ("_pad1", ct.c_uint64),
        ("_pad2",ct.c_uint64),
    ]

class KambpfListBuffer(ct.Structure):
    _fields_ = [
        ("fd", ct.c_int),
        ("pages", ct.c_int),
        ("header", ct.POINTER(KambpfListHeader)),
        ("entries",ct.POINTER(KambpfListEntry)),
    ]

from pathlib import Path

lib = ct.CDLL("libkambpf.so")

class Libkambpf:
    open_list_device = lib.kambpf_open_list_device
    open_list_device.restype = ct.POINTER(KambpfListBuffer)
    open_list_device.argtypes = (ct.c_char_p, ct.c_int)

    free_list_device = lib.kambpf_free_list_buffer
    free_list_device.restype = None
    free_list_device.argtypes = (ct.POINTER(KambpfListBuffer),)

    open_updates_device = lib.kambpf_open_updates_device
    open_updates_device.restype = ct.POINTER(None)
    open_updates_device.argtypes = (ct.c_char_p, ct.c_int)

    free_updates_buffer = lib.kambpf_free_updates_buffer
    free_list_device.restype = None
    free_list_device.argtypes = (ct.POINTER(None),)

class KambpfList:
    def __init__(self, path):
        self._list_dev = Libkambpf.open_list_device(ct.c_char_p(path), 10000)
    def get_non_empty_pos(self):
        sol = []
        for i in range(self._list_dev.contents.header.contents.num_entries):
            entry = self._list_dev.contents.entries[i]
            if entry.instruction_address != 0:
                sol.append(i) 
        return sol

class UpdatesBuffer:
    def __init__(self, max_probes = 1000, path = UPDATE_DEVICE_PATH):
        self.probes = []
        self.max_probes = max_probes
        self._ptr = Libkambpf.open_updates_device(ct.c_char_p(path), max_probes)

    def close(self):
        if self._ptr == None:
            return
        self.clear_probes()
        Libkambpf.free_updates_buffer(self._ptr)
        self._ptr = None

    def __del__(self):
        self.close()

    def _add_probes_chunk(self, probes):
        if self._ptr == None:
            return []
        for i,probe in enumerate(probes):
            lib.kambpf_updates_set_entry(self._ptr, ct.c_uint32(i), ct.c_uint64(probe[0]), ct.c_uint32(probe[1]), ct.c_uint32(probe[2]))
        lib.kambpf_submit_updates(self._ptr, len(probes))
        results = []
        for i in range(len(probes)):
            ret = lib.kambpf_updates_get_id(self._ptr, ct.c_uint32(i))
            if ret > 0:
                self.probes.append(ret)
            results.append(ret) 
        return results

    def add_probes(self, probes):
        if self._ptr == None:
            return []
        results = []
        for i in range(0, len(probes), self.max_probes):
            chunk = probes[i : min(len(probes), i+self.max_probes)]
            results.extend(self._add_probes_chunk(chunk))
        return results

    def _clear_probes_chunk(self, probes):
        if self._ptr == None:
            return
        for i, probe in enumerate(probes):
            if  probe > 0:
                lib.kambpf_updates_set_entry_remove(self._ptr, ct.c_uint32(i), ct.c_uint32(probe))
        print("Clearing ",len(probes))
        lib.kambpf_submit_updates(self._ptr, len(probes))

    def clear_probes(self, probes=None):
        if self._ptr == None:
            return
        if probes == None:
            probes = self.probes
        for i in range(0, len(probes), self.max_probes):
            chunk = probes[i : min(len(probes), i+self.max_probes)]
            self._clear_probes_chunk(chunk)
        probes.clear() 
        # A really misdesigned feature, If I want to remove all probes best to have an ioctl for that

if __name__=="__main__":
    l = KambpfList(b"/dev/kambpf_list")
    pos = l.get_non_empty_pos()
    print(pos)
    ub = UpdatesBuffer()
    ub.clear_probes(pos)
