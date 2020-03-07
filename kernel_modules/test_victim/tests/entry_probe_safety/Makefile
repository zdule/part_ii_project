B ?= $(PWD)/build
S ?= $(PWD)

bpf_objects += $B/bpf.o
userland := $B/userland
objs += $(userland).o
progs += $(userland)
$(userland)-objs := $(test_helpers) $(userland).o 
$(userland)-libs := $(libkambpf)
$(userland)-lflags := -lbpf -lelf


