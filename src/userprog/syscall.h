#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"
#include "threads/synch.h"


typedef int pid_t;

void syscall_init (void);
void remove_all_cp(void);
struct parent_child* find_pc(pid_t pid);

struct parent_child{
    pid_t pid;
    int alive_count;
    int status;
    
    int load_status;
    int exit;
    
    struct semaphore sema_load;
    struct semaphore sema_exit;

    struct thread* parent;
    struct list_elem elem;
};

struct process_file{
    struct file* file;
    int fd;
    struct list_elem elem;
};


#endif /* userprog/syscall.h */
