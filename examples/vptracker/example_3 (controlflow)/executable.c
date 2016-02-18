#include <stdio.h>

int afunc(int x, int y) {
  return x*y;
}

int foo(void) {
  int x = 0;
  int y = 0;

  scanf("%d %d", &x, &y);

  int z = x + y;
  int w = 1;

  ifelse:
    printf("Ciao!\n");
    if (z > 0) {
      w += 1;
    } else {
      w -= 1;
    }

  whileloop:
    while(x > 0) {
      w += 1;
      x -= 1;
    }

  switchcase:
    switch(afunc(z,y)) {

    case 0:
    y = 0;
    break;

    case 5:
    y = 1;
    break;

    case 10:
    y = 2;
    break;

    default:
    y = 3;
    break;

    }

  if (z < 0) {
    goto ifelse;
  }

  return 0;
}


/*

myfunc:
	pushq	%rbp
	movq	%rsp, %rbp
	movl	%edi, -4(%rbp)      // edi = x
	movl	%esi, -8(%rbp)      // esi = y
	movl	-4(%rbp), %eax
	imull	-8(%rbp), %eax      // eax = x*y
	popq	%rbp
	ret
.LC0:
	.string	"%d %d\n"
	.text
	.globl	main
	.type	main, @function
main:
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp
	movl	%edi, -20(%rbp)     // edi = argc
	movq	%rsi, -32(%rbp)     // rsi = **argv
	movl	$0, -12(%rbp)
	movl	$0, -16(%rbp)
	leaq	-16(%rbp), %rdx     // rdx = &y
	leaq	-12(%rbp), %rax     // rax = &x
	movq	%rax, %rsi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	__isoc99_scanf
	movl	-12(%rbp), %edx     // edx = x
	movl	-16(%rbp), %eax     // eax = y
	addl	%edx, %eax          // eax = z = x+y
	movl	%eax, -8(%rbp)
	movl	$1, -4(%rbp)        // w
.L4:
	cmpl	$0, -8(%rbp)
	jle	.L5                   // if z <= 0
	addl	$1, -4(%rbp)        // w += 1
	jmp	.L7
.L5:                        // if z > 0
	subl	$1, -4(%rbp)        // w -= 1
.L6:
	jmp	.L7
.L8:
	addl	$1, -4(%rbp)        // w += 1
	movl	-12(%rbp), %eax     // eax = x
	subl	$1, %eax            // x -= 1
	movl	%eax, -12(%rbp)
.L7:
	movl	-12(%rbp), %eax     // eax = x
	testl	%eax, %eax
	jg	.L8                   // while x > 0
.L9:                        // if x <= 0
	movl	-16(%rbp), %edx
	movl	-8(%rbp), %eax
	movl	%edx, %esi          // esi = edx = y
	movl	%eax, %edi          // edi = eax = z
	call	myfunc              // eax = myfunc(z,y)
	cmpl	$5, %eax
	je	.L11                  // case eax = 5
	cmpl	$10, %eax
	je	.L12                  // case eax = 10
	testl	%eax, %eax
	jne	.L17                  // case eax != 0 (default)
	movl	$0, -16(%rbp)       // y = 0
	jmp	.L14
.L11:
	movl	$1, -16(%rbp)       // y = 1
	jmp	.L14
.L12:
	movl	$2, -16(%rbp)       // y = 2
	jmp	.L14
.L17:
	movl	$3, -16(%rbp)       // y = 3
	nop                       // break on default (useless)
.L14:
	cmpl	$0, -8(%rbp)
	jns	.L15                  // if z >= 0
	jmp	.L4                   // goto ifelse;
.L15:
	movl	$0, %eax
	leave
	ret

*/
