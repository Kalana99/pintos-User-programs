#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/stdio.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler (struct intr_frame *);

static struct lock f_lock; //avoids any race conditions while accessing files

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&f_lock);
}

/* each pointer used in system calls are validated to ensure that they are
in the user memory space and valid to use.
If any of these addresses contains a pointer stored in them, they are 
also validated. */

static void
syscall_handler (struct intr_frame *f UNUSED) 
{ 
  validate_address(f->esp);

  int * arg_ptr = (int *)f->esp;

  //system call number
  int call_no = *(arg_ptr);

  //get the address of the first argument(filename) and validate
  arg_ptr++;
  validate_address(arg_ptr);

  switch (call_no){

    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:;
      int status = *(arg_ptr);
      exit(status);
      break;

    case SYS_EXEC:;
      const char * cmd_line = *arg_ptr;
      f -> eax = exec(cmd_line);
      break;

    case SYS_WAIT:;
      int pid = *arg_ptr;
      f -> eax = wait(pid);
      break;

    case SYS_CREATE:
      f->eax = two_argument_parse(SYS_CREATE, arg_ptr);
      break;

    case SYS_REMOVE:
      f->eax = remove(arg_ptr);
      break;

    case SYS_OPEN:;
      const char * file = *arg_ptr;
      f->eax = open(file);
      break;

    case SYS_FILESIZE:;
      int fd_size = *(arg_ptr);
      f->eax = filesize(fd_size);
      break;

    case SYS_READ:
      f->eax = three_argument_parse(SYS_READ, arg_ptr);
      break;

    case SYS_WRITE:
      f->eax = three_argument_parse(SYS_WRITE, arg_ptr);
      break;

    case SYS_SEEK:
      two_argument_parse(SYS_SEEK, arg_ptr);
      break;

    case SYS_TELL:;
      int fd_tell = *(arg_ptr);
      f->eax = tell(fd_tell);
      break;

    case SYS_CLOSE:;
      int fd_close = *(arg_ptr);
      close(fd_close);
      break;
    
    default:
      break;
  }
}

void halt(){
  shutdown_power_off();
}

void exit(int status){
  thread_exit(status);
}

tid_t exec (const char *cmd_line){
  validate_address(cmd_line);
  return process_execute(cmd_line);
}

int wait (tid_t pid){
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size){

  lock_acquire(&f_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&f_lock);

  return success;
}

bool remove (const char *file){

  validate_address(file);

  lock_acquire(&f_lock);
  bool success = filesys_remove(file);
  lock_release(&f_lock);

  return success;
}

int open (const char *file){

  validate_address(file);

  int return_fd = -1;

  lock_acquire(&f_lock);

  struct thread * cur = thread_current ();
  struct file * opened_file = filesys_open(file);

  lock_release(&f_lock);

  //if the file is opened successfully, returns the descriptor, else -1
  if(opened_file != NULL){
    
    return_fd = cur->fd;
    cur->fd = cur->fd + 1;

    *(cur->fdt + return_fd) = opened_file;
  }
  return return_fd;
}

int filesize (int fd){

  /* 0 and 1 are pre-defined descriptors, so fd must not be one of them
  fd should corresponds to an already opened file
  any other fd will cause to return -1 */
  if(fd > thread_current()->fd || fd < 2){
    return -1;
  }

  struct file * f = *(thread_current()->fdt + fd);

  lock_acquire(&f_lock);
  int return_size = file_length(f);
  lock_release(&f_lock);

  return return_size;
}

int read (int fd, void *buffer, unsigned size){

  int read_size = -1;

  if(fd == 0){

    //reads from keyboard(STDIN)
    read_size = 0;

    while(read_size < size){
      input_getc();
    }

    read_size = size;
  }
  else if(fd > 1){

    //checks the fd validity
    if(fd >= thread_current()->fd || fd < 0){
      return -1;
    }

    struct file * f = *(thread_current()->fdt + fd);

    if(f == NULL){
      return -1;
    }

    lock_acquire(&f_lock);
    read_size = file_read(f, buffer, size);
    lock_release(&f_lock);

    //desired size is not read due to some error
    if(read_size < (int)size){
        return -1;
    }
  }
  return read_size;
}

int write (int fd, const void *buffer, unsigned size){

  int write_size = -1;

  //writes to console(STDOUT)
  if(fd == 1){
    putbuf((char *)buffer, size);
    return (int)size;
  }
  else if(fd > 1){

    //checks the fd validity
    if(fd >= thread_current()->fd || fd < 0){
      return -1;
    }

    struct file * f = *(thread_current()->fdt + fd);

    if(f == NULL){
      return -1;
    }

    // if(thread_current()->running_file_check->f)

    lock_acquire(&f_lock);
    write_size = file_write(f, buffer, size);
    lock_release(&f_lock);

    //desired size is not written due to some error
    if(write_size < (int)size){
        return -1;
    }
  }
  return write_size;
}

void seek (int fd, unsigned position){

  if(fd > thread_current()->fd || fd < 0){
    return;
  }

  struct file * f = *(thread_current()->fdt + fd);

  if(f == NULL){
    return;
  }

  lock_acquire(&f_lock);
  file_seek(f, position);
  lock_release(&f_lock);
}

unsigned tell (int fd){

  if(fd > thread_current()->fd || fd < 0){
    return -1;
  }

  struct file * f = *(thread_current()->fdt + fd);

  if(f == NULL){
    return -1;
  }

  lock_acquire(&f_lock);
  unsigned return_byte = file_tell(f);
  lock_release(&f_lock);

  return return_byte;
}

void close (int fd){

  if(fd >= thread_current()->fd || fd < 2){
    return;
  }

  struct file * f = *(thread_current()->fdt + fd);

  if(f == NULL){
    return;
  }

  lock_acquire(&f_lock);
  file_close(f);
  *(thread_current()->fdt + fd) = NULL;
  lock_release(&f_lock);
}

void validate_address (void *pointer){

  //validate the last address of the argument pointer
  pointer = (char *)pointer + 3;

  if (!is_user_vaddr(pointer)){
    //if the address is not in user space, exit
    exit(-1);
  }
  else if(pagedir_get_page(thread_current()->pagedir, pointer) == NULL){
    //if the address is not mapped, exit
    exit(-1);
  }
}

int three_argument_parse(int type, int * arg_ptr){

  //validate arg_ptr in every increment
  int fd = *arg_ptr;

  arg_ptr++;
  validate_address(arg_ptr);
  char* buffer = *arg_ptr;
  validate_address(buffer);

  arg_ptr++;
  validate_address(arg_ptr);
  int size = *arg_ptr;

  if(type == SYS_WRITE){
    //either writes to the console or a file
    return write(fd, buffer, size);
  }
  else if(type == SYS_READ){
    return read(fd, buffer, size);
  }
}

int two_argument_parse(int type, int * arg_ptr){

  if (type == SYS_CREATE){

    char * file = *arg_ptr;
    validate_address(file);

    arg_ptr++;
    validate_address(arg_ptr);
    int init_size = *arg_ptr;

    return create(file, init_size);
  }
  else if (type == SYS_CREATE){
    
    int fd = *arg_ptr;

    arg_ptr++;
    unsigned position = *arg_ptr;

    seek(fd, position);
  }
  return 0;
}
