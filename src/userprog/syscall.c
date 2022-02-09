#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "lib/kernel/stdio.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/init.h"
#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "userprog/process.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
void halt(void);
bool create(const char* file, unsigned initial_size);
int open(const char *file);
void close(int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size); 
void exit(int status); 
pid_t exec(const char* cmd_line);
struct file* aquire_file(int fd);
void read_args(struct intr_frame *f, int* args, int size);

void remove_children(void);
struct child_process* find_child(int pid);
void remove_child(struct child_process* child);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("\nsystem call!\n");
  int* sys_call_no = (int*)f->esp;
  int arg[3];
  switch (*sys_call_no)
  {
  case SYS_HALT:
    printf("\nHalt\n");
    halt();
    break;
  
  case SYS_CREATE:
    printf("\nCreate\n");
    read_args(f, &arg[0], 2);
    bool succesfull = create((const char*)arg[0], (unsigned)arg[1]);
    f->eax = succesfull;
    break;

  case SYS_OPEN:
    printf("\nopen\n");
    read_args(f, &arg[0], 1);
    int result = open((const char*)arg[0]);
    f->eax = result;
    break;
  
  case SYS_CLOSE:
    printf("\nClose\n");
    
    read_args(f, &arg[0], 1);
    close((int)arg[0]);
    break;
  
  case SYS_READ:
    printf("\nRead\n");

    read_args(f, &arg[0], 3);
    int fd = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
    f->eax = fd;
    break;

  case SYS_WRITE:
    //printf("\nWrite\n");
    
    read_args(f, &arg[0], 3);
    int fd_write = write((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
    f->eax = fd_write;
    break;

  case SYS_EXIT:
    printf("\nExit\n");
    read_args(f, &arg[0], 1);
    exit((int)arg[0]);
    break;
  
  case SYS_EXEC:
    printf("\nExec\n");
    read_args(f, &arg[0], 1);
    f->eax = exec((const char*)arg[0]);
    break;
  }

}
void halt(void){
  power_off();
}

bool create(const char* file, unsigned initial_size){
  bool result = filesys_create(file, initial_size);
  return result;
}


int open(const char *file){
  struct file* file_open = filesys_open(file);
  if(!file_open){
    return -1;
  }
  
  struct process_file* p_file = malloc(sizeof(struct process_file));
  p_file->file = file_open; 
  // if(thread_current()->fd > 128) return -1;
  p_file->fd = thread_current()->fd;
  thread_current()->fd ++;
  list_push_back(&thread_current()->files, &p_file->elem);
  return p_file->fd;
}


void close(int fd){
  struct thread* t_curr = thread_current();
  struct list_elem* next;

  for (struct list_elem* i = list_begin(&t_curr->files); i != list_end(&t_curr->files);
        i = next){
          next = list_next(i);
          struct process_file* p_file = list_entry(i, struct process_file, elem);
          if (p_file->fd == fd){
            file_close(p_file->file);
            list_remove(&p_file->elem);
            free(p_file);
          }

        }
}
int read (int fd, void *buffer, unsigned size){
  
  if (fd == 0){
    uint8_t* buffer_d = (uint8_t*) buffer;
    for (unsigned i = 0; i < size; i++ ){
      buffer_d[i] = input_getc();
 
    }
    return size;
  }
 

  struct file* p_file = aquire_file(fd);
  if(!p_file) return -1;
  int length = file_read(p_file, buffer, size);
  return length;

}


int write(int fd, const void* buffer, unsigned size){
  if (fd == 1){
    putbuf(buffer, size);
    return size;
  }

  struct file* p_file = aquire_file(fd);
  if(!p_file) return -1;
  int length = file_write(p_file, buffer, size);
  return length;
}


void exit(int status){
  if (thread_alive(thread_current()->parent) && thread_current()->child_p){
    if (status < 0) status = -1;
    thread_current()->child_p->status = status;
  }
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();

}


pid_t exec(const char* cmd_line){
  pid_t pid = process_execute(cmd_line);
  printf("Hello %d", pid);
  struct child_process* child = find_child(pid);
  if (!child) return -1;
  if(child->load_status == 0) sema_down(&child->s_load);
  if(child->load_status == 2){
    remove_child(child);
    return -1;
  }
  return pid;
}


struct file* aquire_file(int fd){
  struct thread* t_curr = thread_current();
  struct list_elem* next;

  for (struct list_elem* i = list_begin(&t_curr->files); i != list_end(&t_curr->files);
        i = next){
          next = list_next(i);
          struct process_file* p_file = list_entry(i, struct process_file, elem);
          if (p_file->fd == fd){
            return p_file->file;
          }

  }
  return NULL;
}

void read_args(struct intr_frame* f, int* args, int size){
  for(int i = 0 ; i < size; i++){
    args[i] = *((int *) f->esp + i +1 );
  }

}

struct child_process* find_child(int pid){
  struct thread* t = thread_current();
  struct list_elem* e;
  struct list_elem* next;
  for(e = list_begin(&t->children); e != list_end(&t->children); e = next){
    next = list_next(e);
    struct child_process* child = list_entry(e, struct child_process, elem);
    if(child->pid == pid) return child;
  }
  return NULL;
}

void remove_childen(void){
  struct thread* t = thread_current();
  struct list_elem* e;
  struct list_elem* next;
  for(e = list_begin(&t->children); e != list_end(&t->children); e = next){
    next = list_next(e);
    struct child_process* child = list_entry(e, struct child_process, elem);
    list_remove(&child->elem);
    free(child);

    
  }  

}

void remove_child(struct child_process* child){
  list_remove(&child->elem);
  free(child);
}