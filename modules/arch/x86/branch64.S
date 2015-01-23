#ifndef BRANCH_DIM
	#error "È necessario specificare la dimensione della tabella branch_insns specificando la macro BRANCH_DIM"
#endif
#ifndef OFF_DIM
	#error "È necessario specificare la dimensione della tabella branch_offsets specificando la macro OFF_DIM"
#endif

.text

.globl correct_branch
.type	correct_branch, @function
correct_branch:
	
	push	%rax			# Salva %rax nello stack
	push	%rcx 			# Salva i registri nell'ordine di codice numerico usato dall'IS
 	push	%rdx
 	push	%rbx
 	mov	%rsp, %rax 		# Ricostruisce il valore iniziale di %rsp
	sub	$8, %rsp		# Anzichè 4 toglie 8 a rsp (sale di una posizione nello stack)
	add	$32, %rax 		#  (16->32) %rsp è salito di 4 posizioni rispetto all'inizio
	mov	%rax, (%rsp)
 	push	%rbp 			# Salva i valori degli altri registri
 	push	%rsi
 	push	%rdi
	pushfw

	mov	26(%rsp), %rbp		#  (12->24) Crea la finestra dello stack
	sub	$8, %rbp 		#  (4->8) %rbp deve puntare il valore di %rax nello stack

	mov	8(%rbp), %rsi 		#  (4->8) Carica il valore di ritorno della funzione chiamante in %rsi


	# Ricerca binaria nella tabella branch_insns
	xor	%rbx, %rbx		# LOW = 0
	mov	$BRANCH_DIM, %rcx	# HIGH = $DIM_BT
	jmp	.CercaBP
    .HighHalfBP:
	lea	0x1(%rdx), %rbx		# Incrementa di 1 il mediano
	cmp	%rcx, %rbx
	jae	.TrovatoBP
    .CercaBP:
	lea	(%rcx,%rbx,1), %rdx	# low + high
	shr	%rdx			# (low + high) / 2 : mediano
	mov	$24, %rax		# Converte la posizione in uno spiazzamento in byte dall'inizio della tabella
	imul	%rdx, %rax
	cmp	%rsi,branch_insns(%rax)	# Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb	.HighHalfBP		# Controlla se è minore
    .LowHalfBP:
	mov	%rdx, %rcx		# Nuovo high = mediano
	cmp	%rcx, %rbx		# while LOW < HIGH
	jb	.CercaBP
    
    .TrovatoBP:

   	# Carica il campo flags della row corrente
	lea	(,%rcx,4), %rdx
	imul	$6, %rdx		// 4*6 = 24, dimensione di una riga

	movsbq	branch_insns+8(%rdx),%rax
	
    	xor	%rdi, %rdi		# %rdi conterrà l'indirizzo a cui saltare, prima dell'applicazione dello shift
	testb	$4, %al 		# Controlla se c'è un registro indice
	jz	.NoIndex
	movsbq	branch_insns+10(%rdx), %rcx
	negq	%rcx
	movq	(%rbp, %rcx, 8), %rdi	# Salva il valore che era contenuto nel registro indice
	movsbq	branch_insns+11(%rdx),%rcx# Recupera la scala e la moltiplica per l'indice
	imul	%rcx, %rdi

    .NoIndex:
	testb	$2, %al 		# Controlla se c'è un registro di base
	jz	.NoBase
	movsbq	branch_insns+9(%rdx), %rcx
	negq	%rcx
	addq	(%rbp, %rcx, 8), %rdi	# Aggiunge il valore dell'indirizzo di base

    .NoBase:
	add	branch_insns+16(%rdx),%rdi	# Aggiunge l'offset

	# Controlla se il valore del salto era nei registri o in memoria
	testb	$8, %al
	jz	.InReg
	mov	(%rdi), %rdi		# %rdi ora contiene il valore che era contenuto in memoria



    .InReg:    
	# Ricerca binaria nella tabella branch_offsets
	xor	%rbx, %rbx		# LOW = 0
	mov	$OFF_DIM, %rcx		# HIGH = $DIM_BO
	jmp	.CercaOF
    .HighHalfOF:
	lea	0x1(%rdx), %rbx		# Incrementa di 1 il mediano
	cmp	%rcx, %rbx
	jae	.TrovatoOF
    .CercaOF:
	lea	(%rcx,%rbx,1), %rdx	# low + high
	shr	%rdx			# (low + high) / 2 : mediano
	mov	$16, %rax		# Converte la posizione in uno spiazzamento in byte dall'inizio della tabella
	imul	%rdx, %rax

	cmp	%rdi,branch_offsets(%rax)# Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb	.HighHalfOF		# Controlla se è minore
    .LowHalfOF:
	mov	%rdx, %rcx		# Nuovo high = mediano
	cmp	%rcx, %rbx		# while LOW < HIGH
	jb	.CercaOF
	
    .TrovatoOF:

	# Converte l'indice della tabella in uno spiazzamento in byte
	imul	$16, %rcx
	
	# Aggiunge l'offset all'indirizzo della branch 
	add	branch_offsets+8(%rcx), %rdi

	# Sottrae il valore di ritorno dell'istruzione più i cinque byte della jump
	sub	%rsi, %rdi
	sub	$5, %rdi
	
	# %rdi contiene l'indirizzo del salto corretto.
	# %rsi contiene l'indirizzo dell'istruzione da correggere
   
	movl	%edi, 1(%esi)		# La jump da correggere ha un opcode di un byte	

	    
    	popfw
	pop	%rdi 			# Ripristina i registri
 	pop	%rsi
 	pop	%rbp
	add	$8, %rsp		#  (4->8)
 	pop	%rbx
 	pop	%rdx
 	pop	%rcx
	pop	%rax
	ret
