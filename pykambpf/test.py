from libkambpf import KambpfList, UpdatesBuffer
if __name__=="__main__":
    l = KambpfList(b"/dev/kambpf_list")
    ub = UpdatesBuffer()

    probes = [(10000 + i, -1, -1) for i in range(0,1000)]
    ub.set_probes(probes)
    pos = l.get_non_empty_pos()
    print(pos)
    ub.clear_probes(pos)
    pos = l.get_non_empty_pos()
    print(pos)
