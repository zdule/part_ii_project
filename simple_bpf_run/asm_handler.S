.global kamprobe_entry_handler_asm

/* Assumes a "tag" pointer is stored in ESP-8.
   Constructs a pt_regs struct on the stack, bellow the tag pointer.
   Call the c Part of the handler with the tag and pt_regs* as arguments
*/
kamprobe_entry_handler_asm:
    // Load the "tag" pointer from rsp-24 to r11
    movq -24(%rsp), %r11 

    // Since the stack is growing downwards, the pt_regs structure
    // is filled from the back to the front  

    // skip ss, rsp, flags, cs, rip, orig_rax  = 6 registers
    // I dont have a use for these at the moment
    sub $48, %rsp

    // Save argument carrying registers to pass them to the eBPF program
    // But also to restore them at the end of the function
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %rax
    push %r8
    push %r9
    push %r10
    
    // Skip r11, and rbx = 2 registers
    // these don't hold  arguments don't need to be restored
    sub $16, %rsp

    // Save rbp to pass it to eBPF
    push %rbp

    // Skip r12, r13, r14, r15 = 4 registers
    // these dont hold arguments and dont need to be restored
    sub $32, %rsp

    // Now rsp points to the pt_regs structure on the stack
    // From now on I can clobber all the callee-clobbered registers

    mov %r11, %rdi
    mov %rsp, %rsi
    call kamprobe_entry_handler

    // Pop r15, r14, r13, r12, rbp, rbx, r11 = 7 registers
    add $56, %rsp

    // Restore the argument registers
    pop %r10
    pop %r9
    pop %r8
    pop %rax
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    // Pop orig_rax, rip, cs, flags, rsp, cs = 6 register
    add $48, %rsp

    ret
