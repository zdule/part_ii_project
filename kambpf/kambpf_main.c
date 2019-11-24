//#include <linux/init.h>
#include <linux/module.h>   // MODULE macros
#include <linux/fs.h>       // file_operations...
#include <linux/cdev.h>     // cdev
#include <linux/kdev_t.h>   // MKNOD macro
#include <linux/list.h>

#include <kam/probes.h>

#include <linux/slab.h>     // kmalloc

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

struct probe_table_entry {
    unsigned long instruciton_address;
    unsigned long call_destination;
    void *ebpf_program;
    void *data;
    struct list_head empty_entries;
};

/* The probe_table header is contained at the start of the first page.
   After it the table entries are laid out. */
struct probe_table_header {
    size_t num_probes;
};

struct probe_table {
    struct probe_table_header *header;
    size_t num_pages;
    u8 **pages;
    struct list_head emptry_entries;
};


struct kambpf_list_dev {
    struct cdev cdev; 
    struct probe_table table;
};

struct kambpf_list_dev list_dev;

// ===================== probe_table methods =================================

int probe_table_init(struct probe_table *table) {
    table->num_pages = 1;
    table->pages = (u8**) kzalloc(sizeof(u8*)*max_num_pages, GFP_KERNEL);
    if (!table->pages) {
        printk(KERN_WARNING MODULE_NAME ": unable to allocate memory for the probe table.\n");
        return -ENOMEM;
    }

    table->pages[0] = (u8*) __get_free_page(GFP_KERNEL);
    if (!table->pages[0]) {
        printk(KERN_WARNING MODULE_NAME ": unable to allocate a memory page for the probe table.\n");
        kfree(table->pages);
        return -ENOMEM;
    }

    table->header = (struct probe_table_header*) table->pages[0];
    table->header->num_probes = 0;

    INIT_LIST_HEAD(&table->emptry_entries);
    return 0;
}

void probe_table_cleanup(struct probe_table *table) {
    size_t i;
    for(i = 0; i < table->num_pages; i++)
        free_page((unsigned long) table->pages[i]);
    kfree(table->pages);
}


// ===================== kambpf_list file_operations =========================

#include <linux/mm.h>		/* everything */
#include <linux/errno.h>	/* error codes */

void kambpf_list_dev_vma_open(struct vm_area_struct *vma) {}
void kambpf_list_dev_vma_close(struct vm_area_struct *vma) {}

int kambpf_list_dev_vma_fault(struct vm_fault *fault) {
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
    if (filp->f_mode & FMODE_READ)
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

    //memset(&dev->cdev, 0, sizeof(struct cdev));
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

struct kambpf_update_entry {
    unsigned long instruction_address;
    __u32 bpf_program_fd;   // __u32 to be accessible to the userland
    // Set by the module
    size_t table_pos; 
};

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

int process_updates(unsigned long updates_count) {

    return 0;
}

// ======================= kambpf_update_dev_fops ==============================

int kambpf_update_dev_fault(struct vm_fault *fault) {
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

#define IOCTL_MAGIC 0x3D1E
long kambpf_update_dev_ioctl(struct file *filp,
                            unsigned int cmd, unsigned long arg) {
    unsigned long updates_count = arg;
    if (cmd != IOCTL_MAGIC)
        return -ENOTTY;
    return process_updates(updates_count);
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
