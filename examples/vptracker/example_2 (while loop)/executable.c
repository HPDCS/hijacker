#include <stdio.h>

// Se non vengono passati parametri alla funzione (se viene messo void),
// GCC non alloca spazio finché non si eccede il limite massimo della Red Zone
// Altrimenti se il numero di parametri è indefinito GCC è costretto ad allocare
// spazio perché non conosce il numero di argomenti?

// void foo() means "a function foo taking an unspecified number of arguments of unspecified type"
// void foo(void) means "a function foo taking no arguments"

int x;

int foo(void) {
  int y = 5;            // 4 byte
  long long i = 0;      // 8 byte
  // int arr[26];       // 26 * 4 = 104 byte

  // int c;
  // int arr[32];

  // Total: 116 byte
  // Remaining: 12 byte
  // -8 rbp
  // -4 return

  printf("<%#016llx>\n", &y);

  for (; i < y; ++i) {
    x += y;
  }

  return y;
}

/*

foo:
  pushq %rbp
  movq  %rsp, %rbp
  subq  $24, %rsp

WRITE x2
  movl  $5, -12(%rbp)
  movq  $0, -8(%rbp)

  jmp .L2

.L3:

READ x2 (x5)
  movl  x(%rip), %edx
  movl  -12(%rbp), %eax

  addl  %edx, %eax

WRITE x1 (x5)
  movl  %eax, x(%rip)

WRITE/READ x1 (x5)
  addq  $1, -8(%rbp)

.L2:

READ x2 (x6)
  movl  -12(%rbp), %eax
  cltq
  cmpq  -8(%rbp), %rax

  jg  .L3

READ x1
  movl  -12(%rbp), %eax

  leave
  ret

-------------------------------------------------------

Detected memory write at <0x7ffd000addf4> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

DO
Detected memory read at <00000000> of bytes 4
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory write at <00000000> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8
Detected memory read at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

DO
Detected memory read at <00000000> of bytes 4
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory write at <00000000> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8
Detected memory read at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

DO
Detected memory read at <00000000> of bytes 4
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory write at <00000000> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8
Detected memory read at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

DO
Detected memory read at <00000000> of bytes 4
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory write at <00000000> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8
Detected memory read at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

Detected memory read at <00000000> of bytes 4
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory write at <00000000> of bytes 4
Detected memory write at <0x7ffd000addf8> of bytes 8
Detected memory read at <0x7ffd000addf8> of bytes 8

WHILE
Detected memory read at <0x7ffd000addf4> of bytes 4
Detected memory read at <0x7ffd000addf8> of bytes 8

RETURN
Detected memory read at <0x7ffd000addf4> of bytes 4

 */
