#!/usr/bin/env python3

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
