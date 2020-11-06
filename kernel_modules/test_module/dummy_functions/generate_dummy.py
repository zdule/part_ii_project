#!/usr/bin/env python3

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

first_dummy = """
noinline int kambpf_test_dummy_0(int a) {
    return a;
}
"""

dummy_template = """
noinline int kambpf_test_dummy_$0(int a) {
    return kambpf_test_dummy_$1(a+1);
}
"""

print(first_dummy)
for i in range(1,5000):
    print(dummy_template.replace("$0",str(i)).replace("$1",str(i-1)))
