#!/usr/bin/make -f

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

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

