	.file	"executable.c"
	.comm	x,4,4
	.text
	.globl	foo
	.type	foo, @function
foo:
.LFB0:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$24, %rsp
	movl	$5, -12(%rbp)
	movq	$0, -8(%rbp)
	jmp	.L2
.L3:
	movl	x(%rip), %edx
	movl	-12(%rbp), %eax
	addl	%edx, %eax
	movl	%eax, x(%rip)
	addq	$1, -8(%rbp)
.L2:
	movl	-12(%rbp), %eax
	cltq
	cmpq	-8(%rbp), %rax
	jg	.L3
	movl	-12(%rbp), %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	foo, .-foo
	.ident	"GCC: (GNU) 5.1.0"
	.section	.note.GNU-stack,"",@progbits
