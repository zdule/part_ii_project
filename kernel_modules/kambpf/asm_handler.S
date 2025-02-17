/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is offered under two licenses GPLv2 and Apache License Version 2.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

.global kambpf_entry_handler_asm
.global kambpf_return_handler_asm

/*
	x86_64 Linux calling convention
	Calle saved registers: rbx, rbp, r12-15, also rsp, 
	Arguments rdi, rsi, rdx, rcx, r8, r9, r10 (static link)
	
	Return values are stored in rax and rdx

	The goal of the routine bellow is to populate the pt_regs with
	argument registers, or return value registers so that they can
	be read by the bpf. Both entry and return bpf programs also need 
	rip, rbp, and rsp.

	Additionally, the composition "entry_handler o probed_function o
	return_handler" must conform to the calling convention.
	- This means that the probed_function must receive it arguments.
	- It must also receive the correct rbp, rsp
	- The composition must leave the return value in rax, rdx
	- The composition must preserve callee saved registers

	The argument registers are not callee saved, so they can be
	clobbered by running the ebpf program, so we must restore them.
	
	There is no need restore callee saved registers, including
	rsp and rbp, because all called functions preserve them.

	The return value registers are not calle saved, so runnign the
	ebpf program can clobber them, and thus they must be restored.

	The flags, ss, and cs registers are not part of the calling 
	convention, so they are never saved and restored.

	Note that floating point arguments are not part of the kernel
	calling convention as they are not used.

	In summary, entry_handler must save argument registers, rsp, rip,
	rbp, and restore argument registers, and return handler must save 
	return value registers, rsp, rbp, rip, and restore return value
	register. Additionally both handlers must restore the callee
	saved registers which they modify, and this is only rsp.
*/

/* Assumes a "tag" pointer in r11.
   Never store on the stack below rsp, it will get overwritten by 
   interrupt handlers.
   Constructs a pt_regs struct on the stack.
   Call the c Part of the handler with the tag and pt_regs* as arguments.
*/

// Since the stack is growing downwards, the pt_regs structure
// is filled from the back to the front  

kambpf_entry_handler_asm:

	// skip ss
	sub $8, %rsp

	// store rsp, it will be corrected later to have its orignal value
	// (i.e. rsp + 8)
	push %rsp

    // skip flags, cs, rip, orig_rax  = 4 registers
	// rsp was saved previously
	// rip will be set in the c handler
    sub $32, %rsp

    // Save argument carrying registers to pass them to the eBPF program
    // But also to restore them at the end of the function
    push %rdi
    push %rsi
    push %rdx
    push %rcx
	// Skip rax
	sub $8, %rsp
    push %r8
    push %r9
    push %r10
   
    // Skip r11 and rbx
	sub $16, %rsp

    // Save rbp to pass it to eBPF
    push %rbp

    // Skip r12, r13, r14, r15 = 4 registers
    sub $32, %rsp

    // Now rsp points to the pt_regs structure on the stack
    // From now on I can clobber all the argument registers

    // r11 stores the struct kambpf_probe *
    movq %r11, %rdi
    movq %rsp, %rsi
    call kambpf_entry_handler

    // Skip r15, r14, r13, r12, rbp, rbx, r11 = 7 registers
    add $56, %rsp

    // Restore the argument registers
    pop %r10
    pop %r9
    pop %r8
	// Skip rax
	add $8, %rsp
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi

    // Skip orig_rax, rip, cs, flags, rsp, ss = 6 register
    add $48, %rsp

    ret

kambpf_return_handler_asm:
    // Since the stack is growing downwards, the pt_regs structure
    // is filled from the back to the front  
	
	// skip ss
	sub $8, %rsp

	// store rsp, it will be corrected later to have its orignal value
	// (i.e. rsp + 8)
	push %rsp

	// Skip flags, cs, rip, orig_rax, rdi, rsi = 6 register
	// rsp was saved previously
	// rip will be set in the c handler
    sub $48, %rsp
   
	// save the return value register rdx	
    push %rdx

	// skip rcx
	sub $8, %rsp

	// save the return value register rax
    push %rax

	// skip registers r8-r11, rbx = 5 registers
    sub $40, %rsp
    
    // Save rbp to pass it to eBPF
    push %rbp

    // Skip r12, r13, r14, r15 = 4 registers
    sub $32, %rsp

    // Now rsp points to the pt_regs structure on the stack
    // From now on I can clobber all return value registers

    // struct kambpf_probe * was passed in through r11
    movq %r11, %rdi
    movq %rsp, %rsi
    call kambpf_return_handler

    // Skip r15, r14, r13, r12, rbp, rbx, r11-r8 = 10 registers
    add $80, %rsp

	// Restore the rax return value register
    pop %rax

	// Skip rcx
	add $8, %rsp

	// Restore the rdx return value register
    pop %rdx

	// Skip rsi, rdi, orig_rax, rip, cs, flags, rsp, ss = 8 registers
    add $64, %rsp

    ret
