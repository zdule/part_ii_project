.PHONY : all kamprobes kambpf test_victim test_victim_load  test_victim_unload \
		 kambpf_load kambpf_unload  kamprobes_load kamprobes_unload libkambpf

all: kamprobes kambpf test_victim libkambpf

libkambpf:
	make -f libkambpf/Makefile S=libkambpf B=libkambpf/build

kamprobes/build/Makefile:
	mkdir -p kamprobes/build
	cd kamprobes/build && cmake ..

kamprobes: kamprobes/build/Makefile
	cd kamprobes/build && make

kambpf: kamprobes
	cd kambpf && make

test_victim: kambpf
	cd test_victim && make

kamprobes_load: kamprobes
	sudo insmod kamprobes/build/kamprobes.ko || true

kamprobes_unload: kambpf_unload
	sudo rmmod kamprobes || true

kambpf_load: kamprobes_load kambpf
	cd kambpf && sudo ./kambpf_reload.sh load

kambpf_unload: test_victim_unload
	cd kambpf && sudo ./kambpf_reload.sh unload

test_victim_load: kambpf_load test_victim
	cd test_victim && sudo ./test_victim_reload.sh load

test_victim_unload:
	cd test_victim && sudo ./test_victim_reload.sh unload

run_tests: test_victim_unload test_victim_load
	cd test_victim && ./run_tests.sh

run_tracer: libkambpf kambpf_unload kambpf_load
	cd callsites && sudo python3 tracer.py
just_tracer:
	cd callsites && sudo python3 tracer.py

dmesg:
	dmesg
