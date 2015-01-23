#ifndef DIM
 #error "You must specify instruction table size DIM"
#endif

.file "monitor64.S"

.data
messaggio:
	.asciz "Ho trovato una scrittura sull'indirizzo %#08x con valore %d\n"

.text
.globl	monitor
.type	monitor, @function
monitor:

# ESISTE L'ISTRUZIONE PUSHAD che mette nello stack i registri esattamente in quest'ordine.......

	push	%rax			 # Salva %rax nello stack
	push	%rcx 			 # Salva i registri nell'ordine di codice numerico usato dall'IS
 	push	%rdx
 	push	%rbx
 	mov	%rsp, %rax 		 # Ricostruisce il valore iniziale di %rsp
	sub	$8, %rsp		 # Anzichè 4 toglie 8 a rsp (sale di una posizione nello stack)
	add	$32, %rax 		 #  (16->32) %rsp è salito di 4 posizioni rispetto all'inizio
	mov	%rax, (%rsp)
 	push	%rbp 			 # Salva i valori degli altri registri
 	push	%rsi
 	push	%rdi
	pushfw				# salva il registro EFLAGS

	# Controlla se il monitor è disattivato
 	mov	monitor_disabled, %eax
	test	$1, %eax
	jnz	.Fine

	# Incrementa il contatore delle invocazioni del monitor
	addq	$1, monitor_invocations

	mov	26(%rsp), %rbp		 #  (12->24) Crea la finestra dello stack
	sub	$8, %rbp 		 #  (4->8) %rbp deve puntare il valore di %rax nello stack

	mov	8(%rbp), %rsi 		 #  (4->8) Carica il valore di ritorno della funzione chiamante in %rsi



	# Ricerca binaria nella tabella delle istruzioni
	xor	%rbx, %rbx		 # LOW

#ifdef MONITOR_BENCHMARK
	movslq	monitor_table_size, %rcx # HIGH
#else
	mov	$DIM, %rcx # HIGH
#endif

	jmp	.Cerca
    .HighHalf:
	lea	0x1(%rdx), %rbx		 # Incrementa di 1 il mediano
	cmp	%rcx, %rbx
	jae	.Trovato
    .Cerca:
	lea	(%rcx,%rbx,1), %rdx	 # low + high
	shr	%rdx			 # (low + high) / 2

	mov	%rdx, %rax		 # Converte la posizione in uno spiazzamento all'interno della tabella
	imul	$24,%rax		 #   La posizione è data da 24 (dimensione di una riga) * mediano
	cmp	%rsi, insn_table(%rax)	 # Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb     .HighHalf		 # Controlla se è minore
    .LowHalf:
	mov	%rdx, %rcx		 # Nuovo high = mediano
	cmp	%rcx, %rbx		 # while LOW < HIGH
	jb     .Cerca
    .Trovato:


	# Carica il campo flags della row corrente
	lea	(,%rcx,4), %rdx
	imul	$0x6, %rdx
	movsbq	insn_table+12(%rdx),%rax


	#Gestione delle MOVS e STOS
	testb	$1, %al			# Una MOVS?
	jz	.ScritturaNormale	# No...
	movsbq insn_table+8(%rdx), %rsi	# Carica la dimensione del dato
       	imul	-8(%rbp), %rsi		#  (4->8) Carica dallo stack il valore originale di %rcx (numero di elementi) e lo moltiplica per la taglia
	mov	-56(%rbp), %rdi 	#  (28->56) Recupera dallo stack il valore originale di EDI
	pushfw				# Calcola il valore di Direction Flag
	popw	%bx
	bt	$10, %bx		# DF è EFLAGS[10]
	jnc	.DF0			# DF = 0
	sub	%rsi, %rdi		# DF = 1: %rdi viene decrementato. %rdi conteneva la *fine* dell'area di memoria scritta
    .DF0: 				# Qui DF = 0: %rdi viene incrementato: %rdi contiene l'inizio della scrittura e non occorre fare nulla
	jmp .CallDymelor


    .ScritturaNormale:
    	xor	%rdi, %rdi		# %rdi conterrà l'indirizzo iniziale della scrittura
	testb	$4, %al 		# Controlla se c'è un registro indice
	jz	.NoIndex
	movsbq	insn_table+14(%rdx), %rcx
	negq	%rcx
	movq	(%rbp, %rcx, 8), %rdi	# Salva il valore che era contenuto nel registro indice
	movsbq	insn_table+15(%rdx),%rcx# Recupera la scala e la moltiplica per l'indice
	imul	%rcx, %rdi

    .NoIndex:
	testb	$2, %al 		# Controlla se c'è un registro di base
	jz	.NoBase
	movsbq	insn_table+13(%rdx), %rcx
	negq	%rcx
	addq	(%rbp, %rcx, 8), %rdi	# Aggiunge il valore dell'indirizzo di base


    .NoBase:
	add	insn_table+16(%rdx),%rdi# Aggiunge l'offset
	movsbq	insn_table+8(%rdx),%rsi	# Carica la dimensione del dato

    .CallDymelor:

	# %rsi contiene la dimensione (in byte) della movs
	# %rdi contiene l'indirizzo iniziale in cui la movs scriverà

#ifdef NOSTACK
	# Controllo per vedere se siamo nello stack
#	cmp 	%rdi, %rsp		# Nello stack?
#	jb	.Fine			# Se %esp è minore di %edi
#endif


	push %rdi
	push %rsi
	push %rax
	push %rdx
	mov (%rdi), %rdx
	mov %rdi, %rsi
	mov $messaggio, %rdi
	xorl %eax, %eax
	callq printf
	pop %rdx
	pop %rax
	pop %rsi
	pop %rdi

# TODO: qui si devono passare i parametri di interesse alla funzione
	
#	push %rdi
#	push %rsi
#	push %rdx
#	push %rcx
#	mov (%rdi), %rcx	#Passo il valore della variabile
#	mov %rsi, %rdx		#Passo la taglia della variabile
#	mov %rdi, %rsi		#Passo l'indirizzo della variabile
#	mov #Thread, %rdi	#Passo la struttura del thread...come faccio???
#	callq SaveLocalWrite
#	pop %rcx
#	pop %rdx
#	pop %rsi
#	pop %rdi


	#push	%rsi
	#push	%rdi
	sub	$4, %rsp
	movl	%esi, (%rsp)
	sub	$8, %rsp
	mov	%rdi, (%rsp)
	call	dirty_mem
	add	$12, %rsp 
	

    .Fine:
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

.size   monitor, .-monitor
