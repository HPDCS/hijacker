#ifndef DIM
 #error "You must specify instruction table size DIM"
#endif

.globl monitor
.type	monitor, @function
monitor:
	push	%eax			# Salva %eax nello stack
	push	%ecx 			# Salva i registri nell'ordine di codice numerico usato dall'IS
	push	%edx
	push	%ebx
	mov	%esp, %eax 		# Ricostruisce il valore iniziale di %esp
	sub	$4, %esp
	add	$16, %eax 		# %esp è salito di 4 posizioni rispetto all'inizio
	mov	%eax, (%esp)
	push	%ebp 			# Salva i valori degli altri registri
	push	%esi
	push	%edi
	pushfw

	# Controlla se il monitor è disattivato
	mov	monitor_disabled, %eax
	test	$1, %eax
	jnz	.Fine

	# Incrementa il contatore delle invocazioni del monitor
	addl	$1, monitor_invocations

	mov	14(%esp), %ebp		# Crea la finestra dello stack
	sub	$4, %ebp 		# %ebp deve puntare il valore di %eax nello stack

	mov	4(%ebp), %esi 		# Carica il valore di ritorno della funzione chiamante in %esi



	# Ricerca binaria nella tabella delle istruzioni
	xor	%ebx, %ebx		# LOW
	mov	$DIM, %ecx		# HIGH
	jmp	.Cerca
    .HighHalf:
	lea	0x1(%edx), %ebx		# Incrementa di 1 il mediano
	cmp	%ecx, %ebx
	jae	.Trovato
    .Cerca:
	lea	(%ecx,%ebx,1), %edx	# low + high
	shr	%edx			# (low + high) / 2

	mov	%edx, %eax		# Converte la posizione in uno spiazzamento all'interno della tabella
	shl	$0x4,%eax		#   La posizione è data da 16 (dimensione di una riga) * mediano
	cmp	%esi, insn_table(%eax)	# Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb     .HighHalf		# Controlla se è minore
    .LowHalf:
	mov	%edx, %ecx		# Nuovo high = mediano
	cmp	%ecx, %ebx		# while LOW < HIGH
	jb     .Cerca
    .Trovato:


	# Carica il campo flags della row corrente
	lea	(,%ecx,4), %edx
	shl	$0x2, %edx
	movsbl	insn_table+8(%edx),%eax


	#Gestione delle MOVS e STOS
	testb	$1, %al			# Una MOVS?
	jz	.ScritturaNormale	# No...
	movsbl insn_table+4(%edx), %esi	# Carica la dimensione del dato
       	imul	-4(%ebp), %esi		# Carica dallo stack il valore originale di %ecx (numero di elementi) e lo moltiplica per la taglia
	mov	-28(%ebp), %edi 	# Recupera dallo stack il valore originale di EDI
	pushfw				# Calcola il valore di Direction Flag
	popw	%bx
	bt	$10, %bx		# DF è EFLAGS[10]
	jnc	.DF0			# DF = 0
	sub	%esi, %edi		# DF = 1: %edi viene decrementato. %edi conteneva la *fine* dell'area di memoria scritta
    .DF0: 				# Qui DF = 0: %edi viene incrementato: %edi contiene l'inizio della scrittura e non occorre fare nulla
	jmp .CallDymelor


    .ScritturaNormale:
    	xor	%edi, %edi		# %edi conterrà l'indirizzo iniziale della scrittura
	testb	$4, %al 		# Controlla se c'è un registro indice
	jz	.NoIndex
	movsbl	insn_table+10(%edx), %ecx
	negl	%ecx
	movl	(%ebp, %ecx, 4), %edi	# Salva il valore che era contenuto nel registro indice
	movsbl	insn_table+11(%edx),%ecx# Recupera la scala e la moltiplica per l'indice
	imul	%ecx, %edi

    .NoIndex:
	testb	$2, %al 		# Controlla se c'è un registro di base
	jz	.NoBase
	movsbl	insn_table+9(%edx), %ecx
	negl	%ecx
	addl	(%ebp, %ecx, 4), %edi	# Aggiunge il valore dell'indirizzo di base


    .NoBase:
	add	insn_table+12(%edx),%edi# Aggiunge l'offset
	movsbl	insn_table+4(%edx),%esi	# Carica la dimensione del dato

    .CallDymelor:

	# %esi contiene la dimensione (in byte) della movs
	# %edi contiene l'indirizzo iniziale in cui la movs scriverà

#ifdef NOSTACK
	# Controllo per vedere se siamo nello stack
	cmp 	%edi, %esp		# Nello stack?
	jb	.Fine		# Se %esp è minore di %edi
#endif

	push	%esi
	push	%edi
	call	dirty_mem
	addl	$8, %esp

    .Fine:
    	popfw
	pop	%edi 			# Ripristina i registri
	pop	%esi
	pop	%ebp
	add	$4, %esp
	pop	%ebx
	pop	%edx
	pop	%ecx
	pop	%eax
	ret
