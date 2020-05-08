.PHONY : all kamprobes  kambpf test_module test_module_load  test_module_unload \
		 kambpf_load kambpf_unload  kamprobes_load kamprobes_unload libkambpf \
		 kambpf_reload dmesg run_tests

all: kamprobes kambpf test_module libkambpf

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

test_module: kambpf
	cd kernel_modules/test_module && make

kamprobes_load: kamprobes
	sudo ./scripts/kamprobes_reload.sh load

kamprobes_unload: kambpf_unload
	sudo ./scripts/kamprobes_reload.sh unload

kambpf_load: kamprobes_load kambpf
	sudo ./scripts/kambpf_reload.sh load

kambpf_unload: test_module_unload
	sudo ./scripts/kambpf_reload.sh unload

kambpf_reload: kambpf_unload kambpf_load

test_module_load: kambpf_load test_module
	sudo ./scripts/test_module_reload.sh load

test_module_unload:
	sudo ./scripts/test_module_reload.sh unload

run_tests: kamprobes_unload test_module_load
	cd kernel_modules/test_module && ./run_tests.sh

#run_setting_benchmark: kambpf_load test_module_load libkambpf
#	cd evaluation/setting_probes; ./run.sh

bench_setting_probes: kambpf libkambpf test_module_load
	sudo bash -c "source scripts/env.sh; cd evaluation/setting_probes/; ulimit -n 40000; python3 setting_probes.py"

fiotestfiles_dir:
	mkdir -p fiotestfiles

bench_scaling_latency: kambpf libkambpf test_module_load fiotestfiles_dir
	sudo bash -c "source scripts/env.sh; cd evaluation/fio/; ulimit -n 40000; python3 scaling_latency.py latency"

bench_scaling_bandwidth: kambpf libkambpf test_module_load fiotestfiles_dir
	sudo bash -c "source scripts/env.sh; cd evaluation/fio/; ulimit -n 4000; python3 scaling_latency.py bandwidth"

bench_opt_scaling_bandwidth: kambpf libkambpf test_module_load fiotestfiles_dir
	sudo bash -c "source scripts/env.sh; cd evaluation/fio/; ulimit -n 40000; python3 optimized_scaling.py bandwidth"

bench_distribution: kambpf libkambpf fiotestfiles_dir
	sudo bash -c "source scripts/env.sh; cd evaluation/fio/; python3 distribution.py"

test_probe_table: kambpf libkambpf kambpf_load
	sudo bash -c "source scripts/env.sh; cd pykambpf/; python3 test.py"

clean_probes:
	sudo bash -c "source scripts/env.sh; cd pykambpf/; python3 libkambpf.py"

dmesg:
	dmesg
