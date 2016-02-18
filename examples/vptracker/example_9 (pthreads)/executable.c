#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define NUM_THREADS     5

// __thread unsigned long tls_area;
__thread unsigned long tls_buffer[32];
__thread unsigned int tls_area_init = 5;
__thread unsigned int tls_area_init2 = 5;


void *PrintHello(void *threadid)
{
   // *(int *)((char *) tls_area + 4) = 7;
   tls_buffer[2] = 5;

   // unsigned char *addr = &tls_area;
   // addr += 7;

   long tid;
   tid = (long)threadid;
   printf("Hello World! It's me, thread #%ld %lu %lu!\n", tid, tls_buffer,
      tls_area_init, tls_area_init2);
   pthread_exit(NULL);
}

int main (int argc, char *argv[])
{
   pthread_t threads[NUM_THREADS];
   int rc;
   long t;
   for(t=0; t<NUM_THREADS; t++){
      printf("In main: creating thread %ld\n", t);
      rc = pthread_create(&threads[t], NULL, PrintHello, (void *)t);
      if (rc){
         printf("ERROR; return code from pthread_create() is %d\n", rc);
         exit(-1);
      }
   }

   /* Last thing that main() should do */
   pthread_exit(NULL);
}

/*

inc_retry:
   mov $global, %rax
   mov %rax, %rbx
   inc %rbx
   lock cmpxchg $global, %rbx
   jnz inc_retry

dec_retry:
   mov $global, %rax
   mov %rax, %rbx
   dec %rbx
   lock cmpxchg $global, %rbx
   jnz dec_retry

---

mov $arg1, %reg
...
mov $argn, %regn
call <malloc>
mov %rax, %fs:0x0

mov %fs:0x0, %reg
call <free>

 */
