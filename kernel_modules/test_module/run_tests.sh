#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

sudo ./build/tests/probes_correctness/entry_probe_userland build/tests/probes_correctness/bpf.o
sudo ./build/tests/probes_safety/userland build/tests/probes_safety/bpf.o
sudo ./build/tests/probes_correctness/return_probe_userland build/tests/probes_correctness/return_bpf.o
