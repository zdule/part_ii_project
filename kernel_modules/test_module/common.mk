#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

SRC_STACK := .
BUILD_STACK := .

define PUSH
$(1:%=%:$(2))
endef

define POP
$(1:%:$(lastword $(subst :, ,$(1)))=%)
endef

define TOP
$(lastword $(subst :, ,$(1)))
endef

define SUBMAKE
SRC_STACK := $$(call PUSH,$$(SRC_STACK),$$(S))
BUILD_STACK := $$(call PUSH,$$(BUILD_STACK),$$(B))
S := $$(S)/$(1)
B := $$(B)/$(1)
include $$(S)/Makefile
S := $$(call TOP,$$(SRC_STACK))
B := $$(call TOP,$$(BUILD_STACK))
SRC_STACK := $$(call POP,$$(SRC_STACK))
BUILD_STACK:= $$(call POP,$$(BUILD_STACK))
endef
