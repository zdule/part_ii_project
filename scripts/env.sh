libkambpf_path=$(pwd)/libkambpf
scripts_path=$(pwd)/scripts

export kambpf_reload=$scripts_path/kambpf_reload.sh
export kamprobes_reload=$scripts_path/kamprobes_reload.sh
export PYTHONPATH="$PYTHONPATH:$(pwd)"
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:$libkambpf_path/build"
