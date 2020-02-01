#ARGS: in probed_function, in return_address, in entry_handler, in ret_handler, out start
# The filename extension must be *CAPITAL* S for the file to be preprocessed
# This would create 
# void *probe_wrapper(void *load_addr, int *bytes_written, 
#					  void *probed_function, void *entry_handler, void *ret_handler, void **start)
#define RETPROBE
.global start

start:
	movq $after_entry, (%rsp)       # sign extended imm32
	jmp entry_handler               # sign extended imm32 offset

after_entry:
	push $return_address            # sign extended imm32

#ifdef RETPROBE
	jnz skip_ret
	movq $pre_retprobe, (%rsp)      # sign extended imm32
skip_ret:
#endif

	jmp probed_function             # sign extended imm32 offset

#ifdef RETPROBE
pre_retprobe:
	push $return_address            # sign extended imm32
	jmp ret_handler                 # sign extended imm32 offset
#endif
