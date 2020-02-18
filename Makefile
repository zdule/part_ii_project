.PHONY : all kamprobes kambpf test_victim test_victim_load  test_victim_unload \
		 kambpf_load kambpf_unload  kamprobes_load kamprobes_unload libkambpf \
		 kambpf_reload

all: kamprobes kambpf test_victim libkambpf

kamprobes:
	cd kamprobes && make

kamprobes_clean:
	cd kamprobes && make mrproper

kambpf: export KAMPROBES_INCLUDE_DIR = $(PWD)/kamprobes/src/include
kambpf: export KAMPROBES_SYMS = $(PWD)/kamprobes/build/Kbuild/Module.symvers
kambpf: kamprobes
	cd kambpf && make

libkambpf:
	make -f libkambpf/Makefile S=libkambpf B=libkambpf/build

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

kambpf_reload: kambpf_unload kambpf_load

test_victim_load: kambpf_load test_victim
	cd test_victim && sudo ./test_victim_reload.sh load

test_victim_unload:
	cd test_victim && sudo ./test_victim_reload.sh unload

run_tests: kamprobes_unload test_victim_load
	cd test_victim && ./run_tests.sh

run_tracer: libkambpf kambpf_reload
	cd callsites && sudo python3 tracer.py

just_tracer:
	cd callsites && sudo python3 tracer.py

dmesg:
	dmesg
