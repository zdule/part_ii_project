.global EPS_traced_caller
.global EPS_call_instruction

// rdi is a pointer to the struct used to pass parameters and record test results
EPS_traced_caller:
	push %r12
    movq (%rdi), %r11   // set: function argument
	movq %r11, %rsi
    push 8(%rdi)        // set: value on top of the stack
    // must not expect caller saved arguments to work
    // the probe function can and will garble them
    movq 16(%rdi), %r12 // set: calle saved register

EPS_call_instruction:
    call EPS_traced_function

    movq (%rsp), %r11 // check: value on top of the stack
	movq %r11, 56(%rdi)
    movq %r12, 64(%rdi) // check: calle saved register
    movq %rax, 72(%rdi)   //check: return value

    pop %rdi
	pop %r12
    ret

EPS_traced_function:
    movq %rsi, 32(%rdi)   // check: rsi function argument
    movq 8(%rsp), %r11 // check: value on top of the stack
	movq %r11, 40(%rdi)
    movq %r12, 48(%rdi)   // check: calle saved register
    movq 24(%rdi), %rax   // set:   return value
    ret 

    
