	.file	"executable.c"
	.comm	variable,4,4
	.comm	var,1,1
	.globl	target
	.data
	.align 4
	.type	target, @object
	.size	target, 4
target:
	.long	10
	.text
	.globl	greater
	.type	greater, @function
greater:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movl	-4(%rbp), %eax
	cmpl	-8(%rbp), %eax
	jle	.L2
	movl	$1, %eax
	jmp	.L3
.L2:
	movl	$0, %eax
.L3:
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	greater, .-greater
	.globl	bar
	.type	bar, @function
bar:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	variable(%rip), %eax
	addl	$1, %eax
	movl	%eax, variable(%rip)
	movl	variable(%rip), %eax
	imull	-4(%rbp), %eax
	movl	%eax, variable(%rip)
	movl	variable(%rip), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	bar, .-bar
	.section	.rodata
.LC0:
	.string	"Iteration %d\n"
.LC1:
	.string	"YES"
.LC2:
	.string	"NO"
	.align 8
.LC3:
	.string	"variable is greater than target(%d)? %s\n"
	.text
	.globl	foo
	.type	foo, @function
foo:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movzbl	var(%rip), %eax
	movl	%eax, %edx
	addl	$1, %edx
	movb	%dl, var(%rip)
	movsbl	%al, %eax
	movl	%eax, %esi
	movl	$.LC0, %edi
	movl	$0, %eax
	call	printf
	movl	target(%rip), %edx
	movl	variable(%rip), %eax
	movl	%edx, %esi
	movl	%eax, %edi
	call	greater
	testl	%eax, %eax
	je	.L7
	movl	$.LC1, %edx
	jmp	.L8
.L7:
	movl	$.LC2, %edx
.L8:
	movl	target(%rip), %eax
	movl	%eax, %esi
	movl	$.LC3, %edi
	movl	$0, %eax
	call	printf
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	foo, .-foo
	.section	.rodata
.LC4:
	.string	"Addr contains to %d\n"
.LC5:
	.string	"Var = %d\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB5:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	subq	$32, %rsp
	movl	%edi, -20(%rbp)
	movq	%rsi, -32(%rbp)
	movl	$1, %edi
	call	malloc
	movq	%rax, -8(%rbp)
	movl	$2, %edi
	call	bar
	movl	%eax, %edx
	movq	-8(%rbp), %rax
	movb	%dl, (%rax)
	movq	-8(%rbp), %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	movl	%eax, %esi
	movl	$.LC4, %edi
	movl	$0, %eax
	call	printf
	jmp	.L10
.L11:
	call	foo
	movl	$3, %edi
	call	bar
	movzbl	var(%rip), %eax
	movl	%eax, %edx
	addl	$1, %edx
	movb	%dl, var(%rip)
	movsbl	%al, %eax
	movl	%eax, %esi
	movl	$.LC5, %edi
	movl	$0, %eax
	call	printf
.L10:
	movzbl	var(%rip), %eax
	cmpb	$19, %al
	jle	.L11
	movl	$0, %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE5:
	.size	main, .-main
	.local	counter.2981
	.comm	counter.2981,4,4
	.ident	"GCC: (GNU) 5.1.0"
	.section	.note.GNU-stack,"",@progbits
