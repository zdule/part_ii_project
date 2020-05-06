.global EPS_traced_caller
.global EPS_call_instruction

// rdi is a pointer to the struct used to pass parameters and record cmpq results
EPS_traced_caller:
    push %rbp
    push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
    
    // save pointer for later
    movq %rdi, %rbx

    // set callee-saved registers
    //movq $43, %rbx
    movq $44, %rbp
    movq $45, %r12
    movq $46, %r13
    movq $47, %r14
    movq $48, %r15

    // set arguments
    movq $49, %rsi
    movq $50, %rdx
    movq $51, %rcx
    movq $52, %r8
    movq $53, %r9

    // set top of stack
    push $54

EPS_call_instruction:
    // make call
    call EPS_traced_function

    // check top of stack
    pop %r11
    movq %r11, (%rbx)
   
    // check return value 
    movq %rax, 16(%rbx)
    movq %rdx, 24(%rbx)

    // check callee-saved arguments
    movq %rbp, 32(%rbx)
    movq %r12, 40(%rbx)
    movq %r13, 48(%rbx)
    movq %r14, 56(%rbx)
    movq %r15, 64(%rbx)

	pop %r15
	pop %r14
	pop %r13
	pop %r12
    pop %rbx
    pop %rbp

    movq $242, %rax
    ret

EPS_traced_function:
    // check top of stack
    movq 8(%rsp), %r11
    movq %r11, 8(%rdi)

    // check arguments
    movq %rsi, 72(%rdi) 
    movq %rdx, 80(%rdi) 
    movq %rcx, 88(%rdi) 
    movq %r8, 96(%rdi) 
    movq %r9, 104(%rdi) 

    movq $55, %rax
    movq $56, %rdx
    ret
