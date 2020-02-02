.PHONY: remote_test rsync

all: remote_test

rsync:
	rsync --exclude="build/" --exclude=".git" -avz . kamprobes_vm:~/part_ii_project

r_%: rsync
	ssh kamprobes_vm "cd part_ii_project && pwd && make $*"

