.PHONY: remote_test rsync

REMOTE ?= kamprobes_vm
all: remote_test

rsync:
	git ls-files -z --recurse-submodules  | rsync --files-from - -avc0 . $(REMOTE):~/part_ii_project
#rsync --exclude="build/" --exclude=".git" -avz . $(REMOTE):~/part_ii_project

r_%: rsync
	ssh $(REMOTE) "cd part_ii_project && pwd && make $*"

get_results:
	scp -r $(REMOTE):~/part_ii_project/callsites/measurements/latest/ .

