#!/usr/bin/env bash

#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

mkdir -p measurements/$3/
scp -r $1:~/part_ii_project/measurements/$2/$4/ measurements/$3/
