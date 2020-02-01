#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Test executing code in memory allocated by module_alloc.");
MODULE_VERSION("0.01");

typedef void *(*alloc_fptr)(unsigned long);
typedef int (*set_flag_fptr)(unsigned long, int);
typedef void (*flush_reset_perms_fptr)(void *);
typedef void *(*text_poke_fptr)(void *, const void*, size_t);

typedef void (*voidf)(void);

alloc_fptr module_alloc_ptr;
flush_reset_perms_fptr flush_reset_perms_ptr;
set_flag_fptr set_memory_ro_ptr;
set_flag_fptr set_memory_x_ptr;
text_poke_fptr text_poke_ptr;

void __init init_function_ptrs(void) {
	module_alloc_ptr = (alloc_fptr) kallsyms_lookup_name("module_alloc");
	set_memory_ro_ptr = (set_flag_fptr) kallsyms_lookup_name("set_memory_ro");
	set_memory_x_ptr = (set_flag_fptr) kallsyms_lookup_name("set_memory_x");
	text_poke_ptr = (text_poke_fptr) kallsyms_lookup_name("text_poke");
}


// inspired by https://elixir.bootlin.com/linux/v5.4-rc5/source/arch/x86/kernel/kprobes/core.c#L416
void *alloc_insn_pages(int npages) {
	void *buf = module_alloc_ptr(npages*PAGE_SIZE);
	if (!buf) 
		return NULL;

	// Original code does this
	// Disallow freeing the page in an interrupt or in vfree_atomic
	// why do this? does it work with multiple pages?
	// not available in linux 4.15
	// flush_reset_perms_ptr(buf);

	set_memory_ro_ptr((unsigned long) buf, npages);
	set_memory_x_ptr((unsigned long) buf, npages);
	return buf;
}

static int __init module_alloc_test_init(void) {
	init_function_ptrs();
    printk(KERN_INFO "module_alloc_test load started\n");
	void *buf = alloc_insn_pages(1);
	printk(KERN_INFO "allocated executable memory %px\n",buf);

	u8 ret_opcode = 0xC3;
	text_poke_ptr(buf,&ret_opcode,1);
	voidf noop = (voidf) buf;

	noop();

	printk(KERN_INFO "module_alloc_test load ended\n");
    return 0;
}

static void __exit module_alloc_test_exit(void) {
    printk(KERN_INFO "module_alloc_test unloaded\n");
}

module_init(module_alloc_test_init);
module_exit(module_alloc_test_exit);
