#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

B ?= $(PWD)/build
S ?= $(PWD)

bpf_objects += $B/bpf.o
userland := $B/userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf -lstdc++


