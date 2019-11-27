#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>  
#include <sys/mman.h>
#include <unistd.h> // getpagesize();

#include <linux/bpf.h>
#include "kambpf_user.h"

const char list_dev[] = "/dev/kambpf_list";
const char update_dev[] = "/dev/kambpf_update";
const char test_victim_dev[] = "/dev/test_victim";

unsigned long get_test_address(){
    int fd = open(test_victim_dev, O_RDONLY);
    unsigned long addr;
    if (!fd) {
        perror("Error ioctling the test victim");
        exit(1);
    }
    ioctl(fd, 1, &addr); 
    close(fd);
    return addr;
}

void trigger_test() {
    int fd = open(test_victim_dev, O_RDONLY);
    if (!fd) {
        perror("Error ioctling the test victim");
        exit(1);
    }
    ioctl(fd, 42, 117); 
    close(fd);
}

int main(int argc, char **argv) {
    int err = 0;
    int i;
    int fd_list, fd_update;
    void *list_start, *update_start;
    struct probe_table_header *header;
    struct probe_table_entry *entries;
    struct kambpf_update_entry *update_entries;

    fd_list = open(list_dev, O_RDONLY);
    if (fd_list < 0) {
        perror("Opening list_dev failed");
        return -1;
    }

    list_start = mmap(0, 4*getpagesize(), PROT_READ , MAP_SHARED, fd_list, 0);
    if (list_start == MAP_FAILED) {
        perror("mmaping list_dev failed");
        err = -1;
        goto failed_map_list;
    }

    header = (struct probe_table_header *) list_start;
    printf("HEADER: %ld %ld %ld\n", header->num_entries, header->start_offset, header->max_num_entries);

    entries = (struct probe_table_entry *) (list_start + header->start_offset);

    fd_update = open(update_dev, O_RDWR);
    if (fd_update < 0) {
        perror("Opening update_dev failed");
        err = -1;
        goto failed_open_update;
    }

    update_start = mmap(0, 4*getpagesize(), PROT_READ | PROT_WRITE, MAP_SHARED, fd_update, 0);
    if (update_start == MAP_FAILED) {
        perror("mmaping update_dev failed");
        err = -1;
        goto failed_map_update;
    }

    update_entries = (struct kambpf_update_entry *) update_start;

    for(i = 0; i < 20; i++) {
        update_entries[i].instruction_address = 100+i;
        update_entries[i].bpf_program_fd = -1;
    }
    ioctl(fd_update, IOCTL_MAGIC, (unsigned long) 20);

    printf("HEADER: %ld %ld %ld\n", header->num_entries, header->start_offset, header->max_num_entries);
    
    puts("TABLE");
    for(i = 0; i < header->num_entries; i++) {
        printf("%d %ld\n",i,entries[i].instruciton_address);
    }
    puts("RETURNED table_pos");
    for(i = 0; i < 20; i++) {
        printf("%d %d\n", i, update_entries[i].table_pos);
    }

    if (argc >= 3) {
        update_entries[0].instruction_address = get_test_address();
        update_entries[0].bpf_program_fd = argc;
        ioctl(fd_update, IOCTL_MAGIC, (unsigned long) 1);
        trigger_test();
        trigger_test();
        trigger_test();
    }

    munmap(update_start, 4*getpagesize());
failed_map_update:
    close(fd_update);
failed_open_update:
    munmap(list_start, 4*getpagesize()); 
failed_map_list:
    close(fd_list);
    return err;
}
