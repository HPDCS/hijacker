#include <stdio.h>
#include <stdlib.h>

int zero(int x, int y) {
  return 0;
}

int add(int x, int y) {
  return x+y;
}

int mul(int x, int y) {
  return x*y;
}

int (* algebra[20])(int x, int y) = {
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, &mul,
  &add, ((void *) (((unsigned long long) &mul) +4 -4))
};

int foo(void) {
  int x, y, opid;
  int (* op)(int x, int y);
  int res_zero, res_op;
  int i;

  PARSEINPUT:
  scanf("%d %d %d", &x, &y, &opid);
  /* if (argc == 4) {
    x = atoi(argv[1]);
    y = atoi(argv[2]);
    opid = atoi(argv[3]);
  } */

  CALLFUNCS:
  op = &zero;
  res_zero = (*op)(x, y);
  res_op = (*(algebra[opid]))(x,y);

  printf("Qui ci arrivo?\n");

  // PRINTRES:
  // printf("zero: %d, op: %d\n");
}


/*

main:
  pushq %rbp
  movq  %rsp, %rbp
  subq  $208, %rsp
  movl  %edi, -196(%rbp)
  movq  %rsi, -208(%rbp)
.L8:
  movl  $0, -16(%rbp)

POPULATE:
  jmp .L9
.L10:
  movl  -16(%rbp), %eax
  cltq
  movq  $add, -192(%rbp,%rax,8)
  movl  -16(%rbp), %eax
  addl  $1, %eax
  cltq
  movq  $mul, -192(%rbp,%rax,8)
  addl  $2, -16(%rbp)
.L9:
  cmpl  $19, -16(%rbp)
  jle .L10

PARSEINPUT:
.L11:
  cmpl  $4, -196(%rbp)
  jne .L12
  movq  -208(%rbp), %rax
  addq  $8, %rax
  movq  (%rax), %rax
  movq  %rax, %rdi
  call  atoi
  movl  %eax, -4(%rbp)
  movq  -208(%rbp), %rax
  addq  $16, %rax
  movq  (%rax), %rax
  movq  %rax, %rdi
  call  atoi
  movl  %eax, -8(%rbp)
  movq  -208(%rbp), %rax
  addq  $24, %rax
  movq  (%rax), %rax
  movq  %rax, %rdi
  call  atoi
  movl  %eax, -12(%rbp)

CALLFUNCS:
.L12:
  movq  $zero, -24(%rbp)
  movl  -8(%rbp), %ecx
  movl  -4(%rbp), %edx
  movq  -24(%rbp), %rax
  movl  %ecx, %esi
  movl  %edx, %edi
  call  *%rax
  movl  %eax, -28(%rbp)
  movl  -12(%rbp), %eax
  cltq
  movq  -192(%rbp,%rax,8), %rax
  movl  -8(%rbp), %ecx
  movl  -4(%rbp), %edx
  movl  %ecx, %esi
  movl  %edx, %edi
  call  *%rax
  movl  %eax, -32(%rbp)

PRINTRES:
.L13:
  movl  $.LC0, %edi
  movl  $0, %eax
  call  printf
  movl  $0, %eax
  leave
  ret

 */
