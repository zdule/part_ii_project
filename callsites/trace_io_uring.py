import sys
from call_graph import CallGraph
from bcc import BPF

prog_text = """
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")
#endif
#define volatile(x...) volatile("")

    #include <linux/workqueue.h>  // work_struct
    #include <linux/refcount.h>   // refcount_t
    #include <linux/fs.h>         // kiocb
    #include <uapi/linux/io_uring.h> // __poll_t
    #include <linux/wait.h>         // wait_queue_*
    #include <linux/types.h>        // list_head

    #undef container_of 
    #define container_of(var, type, field) ((type *) ((void *)var - offsetof(type, field)))

    struct io_ring_ctx;
    struct io_uring_sqe;
    struct file;

    // copied from <kernel_source>/fs/io_uring.c
    struct sqe_submit {
        const struct io_uring_sqe	*sqe;
        unsigned short			    index;
        u32				            sequence;
        bool				        has_user;
        bool				        needs_lock;
        bool				        needs_fixed_file;
    };
    // copied from <kernel_source>/fs/io_uring.c
    struct io_poll_iocb {
        struct file			        *file;
        struct wait_queue_head		*head;
        __poll_t			        events;
        bool				        done;
        bool				        canceled;
        struct wait_queue_entry		wait;
    };

    // also copied from <kernel_source>/fs/io_uring.c
    struct io_kiocb {
        union {
            struct file		*file;
            struct kiocb		rw;
            struct io_poll_iocb	poll;
        };

        struct sqe_submit	submit;

        struct io_ring_ctx	*ctx;
        struct list_head	list;
        struct list_head	link_list;
        unsigned int		flags;
        refcount_t		refs;
        u64			user_data;
        u32			result;
        u32			sequence;

        struct work_struct	work;
    };

    struct record {
        u64 queue_entry;
        u64 op_start;
        u64 completion;
    };
    BPF_HASH(records, u64, struct record, 100);
    BPF_PERF_OUTPUT(pipe);

    struct workqueue_struct;
    int tt_queue_work_on(struct pt_regs *ctx, int cpu, struct workqueue_struct *queue, struct work_struct *work) {
        struct io_kiocb *req = container_of(work, struct io_kiocb, work);
        u64 nanos = bpf_ktime_get_ns();
        bpf_trace_printk("queue_work %lx %lu\\n", req, nanos);
        return 0;
    }

    
    int tt_submit_sqe(struct pt_regs *ctx, struct io_ring_ctx *_ctx, struct io_kiocb *req,
			              const struct sqe_submit *s, bool force_nonblock) {
        u64 nanos = bpf_ktime_get_ns();
        bpf_trace_printk("submit_sqe %lx %lu\\n", req, nanos);
        return 0;
    }

    int tt_complete_rw(struct pt_regs *ctx, struct kiocb *kiocb, long res, long res2) {
        u64 nanos = bpf_ktime_get_ns();
        struct io_kiocb *req = container_of(kiocb, struct io_kiocb, rw);
        bpf_trace_printk("submit_sqe %lx %lu\\n", req, nanos);
        return 0;
    }

"""

graph = CallGraph()
io_queue_work_on_addr = graph.get_edges_sites("io_queue_sqe","queue_work_on")[0]
io_complete_r_addr = graph.indirect_calls_from_fun("io_read")[1][0]
io_complete_w_addr = graph.indirect_calls_from_fun("io_write")[1][0]
io_submit_sqe_addr = graph.get_edges_sites("io_sq_wq_submit_work","__io_submit_sqe")[0]

b = BPF(text=prog_text)
b.load_funcs()

from libkambpf import UpdatesBuffer
ub = UpdatesBuffer()

ub.add_probes([
    (io_queue_work_on_addr, b.funcs["tt_queue_work_on"].fd, -1),
    (io_complete_r_addr, b.funcs["tt_complete_rw"].fd, -1),
    (io_complete_w_addr, b.funcs["tt_complete_rw"].fd, -1),
    (io_submit_sqe_addr, b.funcs["tt_submit_sqe"].fd, -1),
])

from time import sleep

try:
    sleep(1000)
finally:
    ub.clear_probes()
