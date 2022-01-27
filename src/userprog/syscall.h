#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

void syscall_init (void);

struct child_process{
    int pid;
    int t_status;
    int status;

    struct list_elem elem;
};

struct process_file{
    struct file* file;
    int fd;
    struct list_elem elem;
};

#endif /* userprog/syscall.h */
