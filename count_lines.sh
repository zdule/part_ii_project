#!/bin/bash

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

cloc . --exclude-dir=measurements,kamprobes --not-match-f='dummy.c|compile_commands'
# Add 45 lines of diffs to kamprobes repository
# measured with:
# cloc --git --diff 9b0a3d5138f31ad6aacba0fb9cb0208f4701805e HEAD
# inside the kamprobes subrepo
