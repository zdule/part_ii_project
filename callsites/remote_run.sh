rsync -avz * -e ssh kamprobes_vm:~/callsites
ssh kamprobes_vm callsites/run.sh
