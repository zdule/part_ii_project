
parent_dir=$(dirname "$BASH_SOURCE[0]") 
export project_dir=$(realpath "$parent_dir/..")
export scripts=$project_dir/scripts

export kambpf_reload=$scripts/kambpf_reload.sh
export kamprobes_reload=$scripts/kamprobes_reload.sh
export PYTHONPATH="$PYTHONPATH:$project_dir"

libkambpf_path=$project_dir/libkambpf
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$libkambpf_path/build"
