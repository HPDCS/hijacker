#include <stdio.h>
#include <stdlib.h>

int x, y;

int foo(void) {
  scanf("%d", &x);

  y = x + 5;

  switch(x) {
  case 1:
    x++;
    break;

  case 2:
    x++;
    break;

  case 3:
    x++;
    break;

  case 4:
    x++;
    break;

  case 5:
    x++;
    break;

  case 6:
    x++;
    break;

  case 7:
    x++;
    break;

  case 8:
    x++;
    break;

  case 9:
    x++;
    break;

  case 10:
    x++;
    break;

  case 11:
    x++;
    break;

  case 12:
    x++;
    break;

  default:
    x--;
  }

  switch(y) {
  case 1:
    y++;
    break;

  case 2:
    y++;
    break;

  case 3:
    y++;
    break;

  case 4:
    y++;
    break;

  case 5:
    y++;
    break;

  case 6:
    y++;
    break;

  case 7:
    y++;
    break;

  case 8:
    y++;
    break;

  case 9:
    y++;
    break;

  case 10:
    y++;
    break;

  case 11:
    y++;
    break;

  case 12:
    y++;
    break;

  default:
    y--;
  }
}

/*

switch2.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <main>:
   0: 55                    push   %rbp
   1: 48 89 e5              mov    %rsp,%rbp
   4: 48 83 ec 10           sub    $0x10,%rsp
   8: 89 7d fc              mov    %edi,-0x4(%rbp)
   b: 48 89 75 f0           mov    %rsi,-0x10(%rbp)
   f: 48 8b 45 f0           mov    -0x10(%rbp),%rax
  13: 48 83 c0 08           add    $0x8,%rax
  17: 48 8b 00              mov    (%rax),%rax
  1a: 48 89 c7              mov    %rax,%rdi
  1d: e8 00 00 00 00        callq  22 <main+0x22>
  22: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 28 <main+0x28>
  28: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 2e <main+0x2e>
  2e: 83 f8 0c              cmp    $0xc,%eax
  31: 0f 87 e7 00 00 00     ja     11e <main+0x11e>
  37: 89 c0                 mov    %eax,%eax
  39: 48 8b 04 c5 00 00 00  mov    0x0(,%rax,8),%rax
  40: 00
  41: ff e0                 jmpq   *%rax
  43: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 49 <main+0x49>
  49: 83 c0 01              add    $0x1,%eax
  4c: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 52 <main+0x52>
  52: e9 d6 00 00 00        jmpq   12d <main+0x12d>
  57: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 5d <main+0x5d>
  5d: 83 c0 01              add    $0x1,%eax
  60: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 66 <main+0x66>
  66: e9 c2 00 00 00        jmpq   12d <main+0x12d>
  6b: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 71 <main+0x71>
  71: 83 c0 01              add    $0x1,%eax
  74: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 7a <main+0x7a>
  7a: e9 ae 00 00 00        jmpq   12d <main+0x12d>
  7f: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 85 <main+0x85>
  85: 83 c0 01              add    $0x1,%eax
  88: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 8e <main+0x8e>
  8e: e9 9a 00 00 00        jmpq   12d <main+0x12d>
  93: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 99 <main+0x99>
  99: 83 c0 01              add    $0x1,%eax
  9c: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # a2 <main+0xa2>
  a2: e9 86 00 00 00        jmpq   12d <main+0x12d>
  a7: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # ad <main+0xad>
  ad: 83 c0 01              add    $0x1,%eax
  b0: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # b6 <main+0xb6>
  b6: eb 75                 jmp    12d <main+0x12d>
  b8: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # be <main+0xbe>
  be: 83 c0 01              add    $0x1,%eax
  c1: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # c7 <main+0xc7>
  c7: eb 64                 jmp    12d <main+0x12d>
  c9: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # cf <main+0xcf>
  cf: 83 c0 01              add    $0x1,%eax
  d2: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # d8 <main+0xd8>
  d8: eb 53                 jmp    12d <main+0x12d>
  da: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # e0 <main+0xe0>
  e0: 83 c0 01              add    $0x1,%eax
  e3: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # e9 <main+0xe9>
  e9: eb 42                 jmp    12d <main+0x12d>
  eb: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # f1 <main+0xf1>
  f1: 83 c0 01              add    $0x1,%eax
  f4: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # fa <main+0xfa>
  fa: eb 31                 jmp    12d <main+0x12d>
  fc: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 102 <main+0x102>
 102: 83 c0 01              add    $0x1,%eax
 105: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 10b <main+0x10b>
 10b: eb 20                 jmp    12d <main+0x12d>
 10d: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 113 <main+0x113>
 113: 83 c0 01              add    $0x1,%eax
 116: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 11c <main+0x11c>
 11c: eb 0f                 jmp    12d <main+0x12d>
 11e: 8b 05 00 00 00 00     mov    0x0(%rip),%eax        # 124 <main+0x124>
 124: 83 e8 01              sub    $0x1,%eax
 127: 89 05 00 00 00 00     mov    %eax,0x0(%rip)        # 12d <main+0x12d>
 12d: b8 00 00 00 00        mov    $0x0,%eax
 132: c9                    leaveq
 133: c3                    retq

 */
