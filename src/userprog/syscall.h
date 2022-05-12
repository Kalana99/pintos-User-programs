#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

typedef int pid_t;

void syscall_init (void);

void halt (void);
void exit(int);
tid_t exec (const char *);
int wait (tid_t);

bool create (const char *, unsigned);
bool remove (const char *);
int open (const char *);
int filesize (int);
int read (int, void *, unsigned);
int write (int, const void *, unsigned);
void seek (int, unsigned);
unsigned tell (int);
void close (int);

//make sure all the memory accesses are valid to user programs
void validate_address (void *pointer);

//parse and validate given arguments before they are used in systemcalls
int three_argument_parse(int, int *);
int two_argument_parse(int, int *);

#endif /* userprog/syscall.h */
