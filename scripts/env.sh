#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

parent_dir=$(dirname "$BASH_SOURCE[0]") 
export project_dir=$(realpath "$parent_dir/..")
export scripts=$project_dir/scripts

export kambpf_reload=$scripts/kambpf_reload.sh
export kamprobes_reload=$scripts/kamprobes_reload.sh
export PYTHONPATH="$PYTHONPATH:$project_dir"

libkambpf_path=$project_dir/libkambpf
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$libkambpf_path/build"
