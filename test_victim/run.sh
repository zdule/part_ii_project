cd test_victim
make
sudo ./test_victim_reload.sh
sudo ./build/tests/entry_probe_correctness/userland build/tests/entry_probe_correctness/bpf.o
sudo ./build/tests/entry_probe_safety/userland build/tests/entry_probe_safety/bpf.o
