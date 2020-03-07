# Removes a file given in its first argument if it exists
ensure_file_deleted() {
    if test -f $1; then 
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
    lsmode | grep -wq $1
}
