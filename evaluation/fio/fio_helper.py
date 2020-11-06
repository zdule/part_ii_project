#   This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the project.
#
#   Copyright 2020 Dusan Zivanovic

from subprocess import Popen
from trace_io_uring import IOUringTracer

def run_fio(job_path, log_path, log_type='json', latency_log=False):
    latency_log_options = ['--write_lat_log', log_path] if latency_log else []
    fio = Popen(['fio', job_path, '--output', log_path, '--output-format', log_type] + latency_log_options)

def run_traced_fio(probing_mechanism, job_path, log_path, log_type='json', latency_log=False, post_probing_cb=None):
    """
        Run a fio benchmark while tracing io_uring

        param probing_mechanism: The probing mechanism to use for io_uring.
                                 Options are no_probes, kprobes, kambpfprobes.
        param job_path: Path to the fio job to run.
        param log_path: Path at which to save output log.
        param log_type: Log type for fio. Common choices are json and json+.
    """

    tracer = IOUringTracer()
    tracer.add_probes(probing_mechanism)

    if post_probing_cb is not None:
        post_probing_cb()
    
    run_fio(job_path, log_path, log_type, latency_log)
    while True:
        for _ in range(20):
            tracer.receive_messages()
        if fio.poll() != None:
            break 

    tracer.close()
