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
#include <stdlib.h>
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
void halt(void);
bool create(const char* file, unsigned initial_size);
int open(const char *file);
void close(int fd);
int read (int fd, void *buffer, unsigned size);
int write(int fd, const void* buffer, unsigned size); 
void exit(int status); 
int wait(pid_t pid);
pid_t exec(const char* cmd_line);
struct file* aquire_file(int fd);
void read_args(struct intr_frame *f, int* args, int size);

void remove_children(void);

void remove_child(struct child_process* child);
void close_all_files(void);
void validate_pointer(const void* ptr);
void validate_string(const void* string);
void validate_buffer(const void* buffer, unsigned size);
int get_pagepointer(const void* pointer);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  //printf ("\nsystem call!\n");
  int* sys_call_no =(int *) get_pagepointer((const void*)f->esp);
  int arg[3];
  switch (*sys_call_no)
  {
  case SYS_HALT:
    //printf("\nHalt\n");
    halt();
    break;
  
  case SYS_CREATE:
    //printf("\nCreate\n");
    
    read_args(f, &arg[0], 2);
    validate_string((const void*) arg[0]);
    bool succesfull = create((const char*)arg[0], (unsigned)arg[1]);
    f->eax = succesfull;
    break;

  case SYS_OPEN:
    //printf("\nopen\n");
    
    read_args(f, &arg[0], 1);
    validate_string((const void*) arg[0]);
    int result = open((const char*)arg[0]);
    f->eax = result;
    break;
  
  case SYS_CLOSE:
    //printf("\nClose\n");
    
    read_args(f, &arg[0], 1);
    close((int)arg[0]);
    break;
  
  case SYS_READ:
    //printf("\nRead\n");

    read_args(f, &arg[0], 3);
    validate_buffer((const void*) arg[1], (unsigned)arg[2]);
    int fd = read((int)arg[0], (void*)arg[1], (unsigned)arg[2]);
    f->eax = fd;
    break;

  case SYS_WRITE:
    //printf("\nWrite\n");
    
    read_args(f, &arg[0], 3);
    validate_buffer((const void*) arg[1], (unsigned)arg[2]);
    arg[1] = get_pagepointer((const void*) arg[1]);
    int fd_write = write((int)arg[0], (const void*)arg[1], (unsigned)arg[2]);
    f->eax = fd_write;
    break;

  case SYS_EXIT:
    //printf("\nExit\n");
    read_args(f, &arg[0], 1);
    exit((int)arg[0]);
    break;
  
  case SYS_EXEC:
    //printf("\nExec\n");
    read_args(f, &arg[0], 1);

    validate_string((const void*) arg[0]);
    arg[0] = get_pagepointer((const void*) arg[0]);
    f->eax = exec((const char*)arg[0]);
    break;
  
  case SYS_WAIT:
    //printf("\nWait\n");
    read_args(f,&arg[0], 1);
    f->eax = wait((pid_t)arg[0]);
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
  struct thread* cur = thread_current();
  
  if (thread_alive(cur->parent) && cur->child_p){
    if (status < 0) status = -1;
    cur->child_p->status = status;
    //cur->parent->status = status;
  }
  remove_children();
  close_all_files();
  printf("%s: exit(%d)\n", cur->name, status);
  thread_exit();

}


pid_t exec(const char* cmd_line){
  pid_t pid = process_execute(cmd_line);
  struct child_process* child = find_child(pid);

  if (!child){ 
    return -1;}
  if(child->load_status == 0) //not loaded yet wait for sema_up
    sema_down(&child->s_load);
  if(child->load_status == 2){ //failed to load child process

    remove_child(child);
    return -1;
  }
  return pid;
}

int wait(pid_t pid){
  return process_wait(pid);
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
    validate_pointer((const void*) args[i]);
  }

}

struct child_process* find_child(int pid){
  struct thread* t = thread_current();
  struct list_elem* e;
  struct list_elem* next;
  for(e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next){
    next = list_next(e);
    struct child_process* child = list_entry(e, struct child_process, elem);
    if(child->pid == pid) return child;
  }
  return NULL;
}

void remove_children(void){
  struct thread* t = thread_current();
  struct list_elem* e;
  struct list_elem* next;
  for(e = list_begin(&t->child_list); e != list_end(&t->child_list); e = next){
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
void close_all_files(void){
  struct thread* t_curr = thread_current();
  struct list_elem* next;

  for (struct list_elem* i = list_begin(&t_curr->files); i != list_end(&t_curr->files);
        i = next){
          next = list_next(i);
          struct process_file* p_file = list_entry(i, struct process_file, elem);
          
          file_close(p_file->file);
          list_remove(&p_file->elem);
          free(p_file);
          

        }
}

void validate_pointer(const void* ptr){
  if(!is_user_vaddr(ptr) ){
    exit(-1);
  }
}

void  validate_string(const void* string){
  for(;*(char*)get_pagepointer(string) != 0; string = (char*)string +1);
}

void validate_buffer(const void* buffer, unsigned size){
  char* local_buff = (char*) buffer;
  for(unsigned i = 0; i < size; i++){
    validate_pointer((const void*)local_buff);
    local_buff ++;
  }
}

int get_pagepointer(const void* pointer){
  void *ptr = pagedir_get_page(thread_current()->pagedir, pointer);
  if(!ptr) exit(-1);
  return (int)ptr;
}
