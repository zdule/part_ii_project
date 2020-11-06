#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

# Removes a file given in its first argument if it exists
ensure_file_deleted() {
    if test -e $1; then 
        rm $1
    fi
}

# Removes each file given in the arguments if it exists
ensure_files_deleted() {
    for f in $*; do
        ensure_file_deleted $f
    done
}

# Returns true if the module specified in the argument exists
is_loaded() {
    # -w searches for whole words
    # -q means silent
    lsmod | grep -wq $1
}
