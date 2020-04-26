from subprocess import Popen
from trace_io_uring import IOUringTracer

def run_traced_fio(probing_mechanism, job_path, log_path, log_type='json'):
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

    fio = Popen(['fio', job_path, '--output', log_path, '--output-format', log_type])
    while True:
        for _ in range(20):
            tracer.receive_messages()
        if fio.poll() != None:
            break 

    tracer.remove_probes()
