.PHONY : all kamprobes kambpf test_victim test_victim_load  test_victim_unload \
		 kambpf_load kambpf_unload  kamprobes_load kamprobes_unload libkambpf \
		 kambpf_reload

all: kamprobes kambpf test_victim libkambpf

kamprobes:
	cd kernel_modules/kamprobes && make

kamprobes_clean:
	cd kernel_modules/kamprobes && make mrproper

kambpf: export KAMPROBES_INCLUDE_DIR = $(PWD)/kernel_modules/kamprobes/src/include
kambpf: export KAMPROBES_SYMS = $(PWD)/kernel_modules/kamprobes/build/Kbuild/Module.symvers

kambpf: kamprobes
	cd kernel_modules/kambpf && make

libkambpf:
	make -f libkambpf/Makefile S=libkambpf B=libkambpf/build

test_victim: kambpf
	cd test_victim && make

kamprobes_load: kamprobes
	sudo ./scripts/kamprobes_reload.sh load

kamprobes_unload: kambpf_unload
	sudo ./scripts/kamprobes_reload.sh unload

kambpf_load: kamprobes_load kambpf
	sudo ./scripts/kambpf_reload.sh load

kambpf_unload: test_victim_unload
	sudo ./scripts/kambpf_reload.sh unload

kambpf_reload: kambpf_unload kambpf_load

test_victim_load: kambpf_load test_victim
	sudo ./scripts/test_victim_reload.sh load

test_victim_unload:
	sudo ./scripts/test_victim_reload.sh unload

run_tests: kamprobes_unload test_victim_load
	cd kernel_modules/test_victim && ./run_tests.sh

dmesg:
	dmesg
