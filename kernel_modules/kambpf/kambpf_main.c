/*
    This file is part of the kambpf project (https://github.com/zdule/part_ii_project).
    It is file is only offered under the GPLv2 license.
    For more information see the LICENSE file at the root of the project.

    Copyright 2020 Dusan Zivanovic
*/

//#include <linux/init.h>
#include <linux/module.h>   // MODULE macros
#include <linux/fs.h>       // file_operations...
#include <linux/cdev.h>     // cdev
#include <linux/kdev_t.h>   // MKNOD macro
#include <linux/list.h>

#include <kam/probes.h>

#include <linux/slab.h>     // kmalloc

#include "kambpf_kernel.h"
#include "kambpf_probe.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Dusan Zivanovic");
MODULE_DESCRIPTION("Attach ebpf programs to kamprobes.");
MODULE_VERSION("0.01");

#define MODULE_NAME "kambpf"

// ===================== Module Parameters ===============================

uint major_number = 0;
uint max_num_pages = 1000;

module_param(major_number, uint, S_IRUGO);
module_param(max_num_pages, uint, S_IRUGO);

// ======================= kambpf_list_dev datatypes ==============================

struct probe_table {
    struct probe_table_header *header;
    int num_active_probes;

    size_t num_pages;
    struct probe_table_entry **pages;
    struct list_head emptry_entries;
};

const u32 entries_per_page = PAGE_SIZE / sizeof(struct probe_table_entry);
const u32 entries_per_header = sizeof(struct probe_table_header) / 
                               sizeof(struct probe_table_entry);

struct kambpf_list_dev {
    struct cdev cdev; 
    struct probe_table table;
};

struct kambpf_list_dev list_dev;

// ===================== probe_table methods =================================

void probe_table_init_first_page(struct probe_table *table) {
    size_t i;
    struct probe_table_entry *e = table->pages[0];

    for(i = entries_per_header; i < entries_per_page; i++) {
        e[i]._ee.table_pos = i-entries_per_header;
        list_add(&e[i]._ee.empty_entries, &table->emptry_entries);
    }
}

int probe_table_init(struct probe_table *table) {
    table->num_pages = 1;
    table->pages = (struct probe_table_entry **) kzalloc(sizeof(u8*)*max_num_pages, GFP_KERNEL);
    if (!table->pages) {
        printk(KERN_WARNING MODULE_NAME ": unable to allocate memory for the probe table.\n");
        return -ENOMEM;
    }

    table->pages[0] = (struct probe_table_entry *) get_zeroed_page(GFP_KERNEL);
    if (!table->pages[0]) {
        printk(KERN_WARNING MODULE_NAME ": unable to allocate a memory page for the probe table.\n");
        kfree(table->pages);
        return -ENOMEM;
    }

    table->header = (struct probe_table_header*) table->pages[0];
    table->header->num_entries = 0;
    table->header->start_offset = sizeof(struct probe_table_header);
    table->header->max_num_entries = max_num_pages*entries_per_page - entries_per_header;

    table->num_active_probes = 0;

    INIT_LIST_HEAD(&table->emptry_entries);

    probe_table_init_first_page(table);
    return 0;
}

void probe_table_cleanup(struct probe_table *table) {
    size_t i;
    for(i = 0; i < table->num_pages; i++)
        free_page((unsigned long) table->pages[i]);
    kfree(table->pages);
}

void probe_table_erase(struct probe_table *table, u32 index) {
    struct probe_table_entry *e;

    //printk("Table %px index %d\n",table, index);
    // acount for the header, which takes space from the first page
    u32 virtual_index = index + entries_per_header;

    e = table->pages[virtual_index/entries_per_page] + (virtual_index % entries_per_page);

    // Address is zero iff the probe is inactive, no work to be done here.
    // Aditionally must not reinsert entry into the empty_entries list
    if (e->instruciton_address == 0) return;

    // e->data is zero if this entry was test entry, data == kambpf_probe == 0
    if (e->data)
        kambpf_probe_free((struct kambpf_probe *) e->data);
    memset(e, 0, sizeof(struct probe_table_entry));

    e->_ee.table_pos = index;
    list_add(&e->_ee.empty_entries, &table->emptry_entries);
    table->num_active_probes--;
}

bool probe_table_can_accept(struct probe_table *table, u32 additional) {
    return table->header->max_num_entries >= table->num_active_probes + additional;
}

int probe_table_add_page(struct probe_table *table) {
    size_t next_page = table->num_pages;
    struct probe_table_entry *entries;
    size_t i;
    if (next_page == max_num_pages) {
        return -EINVAL;
    }
    table->pages[next_page] = 
        (struct probe_table_entry *) get_zeroed_page(GFP_KERNEL);
    if (!table->pages[next_page]) {
        return -ENOMEM;
    } 
    entries =  table->pages[next_page];
    for(i = 0; i < entries_per_page; i++) {
        entries[i]._ee.table_pos = next_page*entries_per_page + i - entries_per_header;
        list_add(&entries[i]._ee.empty_entries, &table->emptry_entries);
    }
    table->num_pages++;
    return 0;
}

struct probe_table_entry *pop_empty_entry(struct probe_table * table) {
    int err;
    struct _probe_table_empty_entry *ee;
    struct probe_table_entry *e;
    if (list_empty(&table->emptry_entries)) {
        err = probe_table_add_page(table);
        if (err)
            return ERR_PTR(err);
    }
    ee = list_first_entry(&table->emptry_entries, struct _probe_table_empty_entry, empty_entries);
    list_del(&ee->empty_entries); 
    e = container_of(ee, struct probe_table_entry, _ee);
    return e;
}

int probe_table_insert(struct probe_table *table, unsigned long address,
                        u32 bpf_program_fd, u32 bpf_return_program_fd, u32 *index) {
    int err = 0;
    struct kambpf_probe *kbp = 0;
    struct probe_table_entry *e;

    // These are different constants for the same thing, no program to run
    // They are defined differently as one is an interface to kambpf_probe
    // and the other one the interface to kambpf, hence the conversion code
    // bellow.
    if (bpf_program_fd != KAMBPF_NOOP_FD || bpf_return_program_fd != KAMBPF_NOOP_FD) {
        if (bpf_program_fd == KAMBPF_NOOP_FD)
            bpf_program_fd = KAMBPF_PROBE_NOOP_FD;
        if (bpf_return_program_fd == KAMBPF_NOOP_FD)
            bpf_return_program_fd = KAMBPF_PROBE_NOOP_FD;
        kbp = kambpf_probe_alloc(address, bpf_program_fd, bpf_return_program_fd); 
        if (IS_ERR(kbp)) {
            err = PTR_ERR(kbp);
            goto err;
        }
    }

    e = pop_empty_entry(table);
    if (IS_ERR(e)) { 
        err = PTR_ERR(e);
        goto err;
    }
    *index = e->_ee.table_pos;

    e->data = kbp;
    e->instruciton_address = address;

    if (*index+1 > table->header->num_entries)
        table->header->num_entries = *index+1;
    table->num_active_probes++;
    return 0;

err:
    *index = err;
    return err;
}

// ===================== kambpf_list file_operations =========================

#include <linux/mm.h>		/* everything */
#include <linux/errno.h>	/* error codes */

void kambpf_list_dev_vma_open(struct vm_area_struct *vma) {}
void kambpf_list_dev_vma_close(struct vm_area_struct *vma) {}

vm_fault_t kambpf_list_dev_vma_fault(struct vm_fault *fault) {
    struct probe_table *table = (struct probe_table*) fault->vma->vm_private_data;
    struct page *page;
    if (fault->pgoff > table->num_pages)
        return VM_FAULT_NOPAGE;
    page = virt_to_page(table->pages[fault->pgoff]);

    // We need to increment page's reference count, even though we are sure
    // that our driver will never free it, and will thus always have a reference
    // to this page.
    // get_page is still needed because the kernel will automatically decrement
    // the count every time a process unmaps this page, thus if we don't increment
    // the count here it will hit zero prematurely.
    get_page(page);

    fault->page = page;
    return 0; // minor page fault
}

struct vm_operations_struct kambpf_list_dev_vm_ops = {
    .open = kambpf_list_dev_vma_open,
    .close = kambpf_list_dev_vma_close,
    .fault = kambpf_list_dev_vma_fault,
};

int kambpf_list_dev_mmap(struct file *filp, struct vm_area_struct *vma) {
    vma->vm_ops = &kambpf_list_dev_vm_ops;
    vma->vm_private_data = filp->private_data;
    // This is not necessary, as we make sure that file is read only when opening
    // but I like it non the less :)
    vma->vm_flags &= (~VM_EXEC) & (~VM_WRITE);
    return 0;
}
int kambpf_list_dev_open(struct inode *inode, struct file *filp) {
    if (filp->f_mode & FMODE_WRITE)
        return -EACCES;
    filp->private_data = &list_dev.table;
    return 0;
}

int kambpf_list_dev_release(struct inode *inode, struct file *filp) {
   return 0;
}

loff_t noop_llseek(struct file *filp, loff_t off, int reference) {
    return 0;
}

struct file_operations kambpf_list_dev_fops = {
    .owner = THIS_MODULE,
    .open = kambpf_list_dev_open,
    .release = kambpf_list_dev_release,
    .llseek = noop_llseek,
    .mmap = kambpf_list_dev_mmap,
};

// ======================= kambpf_list_dev methods ===========================

int kambpf_list_dev_init(struct kambpf_list_dev *dev, int devno) {
    int err = 0;

    err = probe_table_init(&dev->table);
    if (err) return err;

    cdev_init(&dev->cdev, &kambpf_list_dev_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &kambpf_list_dev_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        probe_table_cleanup(&dev->table); 
        return err;
    }
    return 0;
}

void kambpf_list_dev_cleanup(struct kambpf_list_dev *dev) {
    probe_table_cleanup(&dev->table);
    cdev_del(&dev->cdev);
}

// ======================== kambpf_update_dev datatypes =======================

struct kambpf_update_buffer {
    size_t num_pages;
    void **pages;
};

struct kambpf_update_dev {
    struct cdev cdev;
};

struct kambpf_update_dev update_dev;

// ======================= kambpf_update_buffer methods ===========================

int kambpf_update_buffer_init(struct kambpf_update_buffer *pages) {
    pages->num_pages = 0; 
    pages->pages = kzalloc(sizeof(void*) * max_num_pages, GFP_KERNEL);
    if (!pages->pages) {
        printk(KERN_WARNING MODULE_NAME ": unable to allocate memory for updates buffer.\n");
        return -ENOMEM;
    }
    return 0;
}

struct kambpf_update_buffer *kambpf_update_buffer_alloc(void) {
    int err = 0;
    struct kambpf_update_buffer *update_buffer =
        (struct kambpf_update_buffer *) kmalloc(sizeof(struct kambpf_update_buffer), GFP_KERNEL);
    if (!update_buffer) {
        return ERR_PTR(-ENOMEM);
    }
    err = kambpf_update_buffer_init(update_buffer);
    if (err)
        return ERR_PTR(err);
    return update_buffer;
}

void kambpf_update_buffer_cleanup(struct kambpf_update_buffer *pages) {
    size_t i;
    for(i = 0; i < pages->num_pages; i++)
        free_page((unsigned long) pages->pages[i]);
    kfree(pages->pages);
}

void kambpf_update_buffer_free(struct kambpf_update_buffer *update_buffer) {
    kambpf_update_buffer_cleanup(update_buffer);
    kfree(update_buffer);
}

long update_buffer_prefix(struct kambpf_update_buffer *update_buffer) {
    unsigned long s = 0;
    size_t i;
    for(i = 0; i < max_num_pages && update_buffer->pages[i]; i++)
        s += PAGE_SIZE;
    return s;
}

void process_update_entry(struct kambpf_update_entry *entry) {
    // address == 0 means that this is a remove operations
    // if address == 0 then we remove the item in table_pos
    if (entry->instruction_address == 0) {
        probe_table_erase(&list_dev.table, entry->table_pos);
    } else {
        u32 index;
        //printk("FDS %d %d\n",entry->bpf_program_fd , entry->bpf_return_program_fd);
        probe_table_insert(&list_dev.table, entry->instruction_address, 
                            entry->bpf_program_fd, entry->bpf_return_program_fd, &index);
        entry->table_pos = index;
    }
}

long process_updates(struct kambpf_update_buffer * update_buffer,
                     unsigned long updates_count) {
    unsigned long off;
    unsigned long i;
    unsigned long pgnum;
    unsigned long prefix_bytes = update_buffer_prefix(update_buffer); 
    size_t entry_width = sizeof(struct kambpf_update_entry);

    if (prefix_bytes / entry_width < updates_count)
        return -EINVAL;
    
    pgnum = 0; 
    off = 0;
    for (i = 0; i < updates_count; i++) {
        if (off >= PAGE_SIZE) {
            off = 0;
            pgnum++;
        } 
        process_update_entry(update_buffer->pages[pgnum] + off);
        off += entry_width;
    }
    return 0;
}

// ======================= kambpf_update_dev_fops ==============================

vm_fault_t kambpf_update_dev_fault(struct vm_fault *fault) {
    struct kambpf_update_buffer *buffer_pages = 
        (struct kambpf_update_buffer *) fault->vma->vm_private_data;

    struct page *page;
    pgoff_t pgoff = fault->pgoff; 
    if (pgoff > max_num_pages)
        return VM_FAULT_NOPAGE;
    if (!buffer_pages->pages[pgoff]) {
        buffer_pages->pages[pgoff] = (void*) __get_free_page(GFP_KERNEL); 
        if (!buffer_pages->pages[pgoff]) {
            printk(KERN_WARNING MODULE_NAME ": unable to allocate a memory page for \
                    for the update mmap for process %ld.\n", (long) current->pid);
            return VM_FAULT_NOPAGE;
        }
    }
    page = virt_to_page(buffer_pages->pages[pgoff]);

    get_page(page);
    fault->page = page;
    return 0; // minor page fault
}

struct vm_operations_struct kambpf_update_dev_vm_ops = {
    .fault = kambpf_update_dev_fault,
};

int kambpf_update_dev_mmap(struct file *filp, struct vm_area_struct *vma) {
    vma->vm_ops = &kambpf_update_dev_vm_ops;
    vma->vm_private_data = filp->private_data;
    return 0;
}

int kambpf_update_dev_open(struct inode *inode, struct file *filp) {
    filp->private_data = kambpf_update_buffer_alloc();
    if (IS_ERR(filp->private_data)) {
        return PTR_ERR(filp->private_data);
    }
    return 0;
}

int kambpf_update_dev_release(struct inode *inode, struct file *filp) {
   kambpf_update_buffer_free(filp->private_data); 
   return 0;
}

long kambpf_update_dev_ioctl(struct file *filp,
                            unsigned int cmd, unsigned long arg) {
    unsigned long updates_count = arg;
    if (cmd != IOCTL_MAGIC)
        return -ENOTTY;
    return process_updates((struct kambpf_update_buffer *) filp->private_data, updates_count);
}

struct file_operations kambpf_update_dev_fops = {
    .owner = THIS_MODULE,
    .open = kambpf_update_dev_open,
    .release = kambpf_update_dev_release,
    .llseek = noop_llseek,
    .mmap = kambpf_update_dev_mmap,
    .unlocked_ioctl = kambpf_update_dev_ioctl,
};

// ======================== kambfp_update_dev methods ========================

int kambpf_update_dev_init(struct kambpf_update_dev *dev, int devno) {
    int err = 0;

    cdev_init(&dev->cdev, &kambpf_update_dev_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &kambpf_update_dev_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    return err;
}

void kambpf_update_dev_cleanup(struct kambpf_update_dev *dev) {
    cdev_del(&dev->cdev);
}

// ======================== major number management ============================

int register_major_num(void) {
    int err = 0;
    if (major_number)
        err = register_chrdev_region(MKDEV(major_number,0), 1, MODULE_NAME);
    else {
        dev_t dev;
        err = alloc_chrdev_region(&dev, 0, 1, MODULE_NAME);
        if (!err)
            major_number = MAJOR(dev); 
    }
    return err;
}

void unregister_major_num(void) {
    unregister_chrdev_region(MKDEV(major_number, 0), 1);
}


// ======================= init / exit ========================================

static int __init kambpf_module_init(void) {
    int err = 0;
    kamprobes_init(8000);
    err = register_major_num();
    if (err)
        goto err_major_num;
    err = kambpf_list_dev_init(&list_dev, MKDEV(major_number,0));
    if (err)
        goto err_list_dev;
    err = kambpf_update_dev_init(&update_dev, MKDEV(major_number,1));
    if (err) 
        goto err_update_dev;

    printk(KERN_INFO MODULE_NAME" loaded.\n");
    return 0;

err_update_dev:
    kambpf_list_dev_cleanup(&list_dev);
err_list_dev:
    unregister_major_num();
err_major_num:
    printk(KERN_INFO MODULE_NAME ": aborting module initalisation.\n");
    return err;
}

static void __exit kambpf_module_exit(void) {
    unregister_major_num();
    kambpf_list_dev_cleanup(&list_dev);
    printk(KERN_INFO MODULE_NAME " unloaded.\n");
}

module_init(kambpf_module_init);
module_exit(kambpf_module_exit);
