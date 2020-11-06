#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

from libkambpf import KambpfList, UpdatesBuffer

if __name__=="__main__":
    l = KambpfList(b"/dev/kambpf_list")
    ub = UpdatesBuffer()
    pos = l.get_non_empty_pos()
    ub.clear_probes(pos)
    pos = l.get_non_empty_pos()
    
    assert len(pos) == 0, f"Unable to clear all probes to start the test. len(pos) = {len(pos)}"
    probes = [(10000 + i, -1, -1) for i in range(0,1000)]
    positions = ub.add_probes(probes)
    assert len(positions) == 1000, f"Return different number of handles to how many were inserted. len(positions) = {len(positions)}"

    pos_to_addr = {pos : 10000 + i for (i, pos) in enumerate(positions)}

    found_probes = l.get_non_empty_addresses()
    assert len(found_probes) == 1000, f"Different number of probes in the table to how many were inserted. len(found_probes) = {len(found_probes)}"
    for pos, addr in l.get_non_empty_addresses():
        assert pos in pos_to_addr, "Found probe at position which the test didn't set it at."
        assert(pos_to_addr[pos] == addr, "Different address in the table to what we inserted.")

    ub.clear_probes([i for (i,_) in found_probes])
    pos = l.get_non_empty_pos()
    assert len(pos) == 0, f"Unable to clear all probes after the test. len(pos) = {len(pos)}"

