#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "threads/synch.h"

void syscall_init (void);
void remove_children(void);
struct child_process* find_child(int pid);

struct child_process{
    int pid;
    int load_status;
    int exit_status;
    int status;
    int wait;
    struct semaphore s_load;
    struct semaphore s_exit;

    struct list_elem elem;
};

struct process_file{
    struct file* file;
    int fd;
    struct list_elem elem;
};


#endif /* userprog/syscall.h */
