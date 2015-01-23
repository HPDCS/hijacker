#ifndef BRANCH_DIM_LIGHT
	#error "È necessario specificare la dimensione della tabella branch_insns specificando la macro BRANCH_DIM_LIGHT"
#endif
#ifndef OFF_DIM_LIGHT
	#error "È necessario specificare la dimensione della tabella branch_offsets specificando la macro OFF_DIM_LIGHT"
#endif

.globl correct_bran_l
.type	correct_bran_l, @function
correct_bran_l:
	
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
 
	mov	14(%esp), %ebp		# Crea la finestra dello stack
	sub	$4, %ebp 		# %ebp deve puntare il valore di %eax nello stack

	mov	4(%ebp), %esi 		# Carica il valore di ritorno della funzione chiamante in %esi
	
	
	# Ricerca binaria nella tabella branch_insns
	xor	%ebx, %ebx		# LOW = 0
	mov	$BRANCH_DIM_LIGHT, %ecx	# HIGH = $DIM_BT
	jmp	.CercaBP
    .HighHalfBP:
	lea	0x1(%edx), %ebx		# Incrementa di 1 il mediano
	cmp	%ecx, %ebx
	jae	.TrovatoBP
    .CercaBP:
	lea	(%ecx,%ebx,1), %edx	# low + high
	shr	%edx			# (low + high) / 2 : mediano
	mov	$12, %eax		# Converte la posizione in uno spiazzamento in byte dall'inizio della tabella
	imul	%edx, %eax
	cmp	%esi,branch_insns_l(%eax)	# Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb	.HighHalfBP		# Controlla se è minore
    .LowHalfBP:
	mov	%edx, %ecx		# Nuovo high = mediano
	cmp	%ecx, %ebx		# while LOW < HIGH
	jb	.CercaBP
    
    .TrovatoBP:

    	# Carica il campo flags della row corrente
	lea	(,%ecx,4), %edx
	imul	$3, %edx		// 3*4 = 12, dimensione di una riga
	movsbl	branch_insns_l+4(%edx),%eax
    
	
    	xor	%edi, %edi		# %edi conterrà l'indirizzo a cui saltare, prima dell'applicazione dello shift
	testb	$4, %al 		# Controlla se c'è un registro indice
	jz	.NoIndex
	movsbl	branch_insns_l+6(%edx), %ecx
	negl	%ecx
	movl	(%ebp, %ecx, 4), %edi	# Salva il valore che era contenuto nel registro indice
	movsbl	branch_insns_l+7(%edx),%ecx# Recupera la scala e la moltiplica per l'indice
	imul	%ecx, %edi

    .NoIndex:
	testb	$2, %al 		# Controlla se c'è un registro di base
	jz	.NoBase
	movsbl	branch_insns_l+5(%edx), %ecx
	negl	%ecx
	addl	(%ebp, %ecx, 4), %edi	# Aggiunge il valore dell'indirizzo di base

    .NoBase:
	add	branch_insns_l+8(%edx),%edi	# Aggiunge l'offset
	
	# Controlla se il valore del salto era nei registri o in memoria
	testb	$8, %al
	jz	.InReg
	mov	(%edi), %edi		# %edi ora contiene il valore che era contenuto in memoria

    .InReg:    
	# Ricerca binaria nella tabella branch_offsets
	xor	%ebx, %ebx		# LOW = 0
	mov	$OFF_DIM_LIGHT, %ecx		# HIGH = $DIM_BO
	jmp	.CercaOF
    .HighHalfOF:
	lea	0x1(%edx), %ebx		# Incrementa di 1 il mediano
	cmp	%ecx, %ebx
	jae	.TrovatoOF
    .CercaOF:
	lea	(%ecx,%ebx,1), %edx	# low + high
	shr	%edx			# (low + high) / 2 : mediano
	mov	$8, %eax		# Converte la posizione in uno spiazzamento in byte dall'inizio della tabella
	imul	%edx, %eax
	cmp	%edi,branch_offsets_l(%eax)# Confronta il valore di ritorno dell'elemento nella tabella con quello del mediano
	jb	.HighHalfOF		# Controlla se è minore
    .LowHalfOF:
	mov	%edx, %ecx		# Nuovo high = mediano
	cmp	%ecx, %ebx		# while LOW < HIGH
	jb	.CercaOF
	
    .TrovatoOF:
	

	# Converte l'indice della tabella in uno spiazzamento in byte
	lea	(,%ecx,4), %ecx
	shl	%ecx
	
	# Aggiunge l'offset all'indirizzo della branch 
	add	branch_offsets_l+4(%ecx), %edi
	
	# Sottrae il valore di ritorno dell'istruzione più i cinque byte della jump
	sub	%esi, %edi
	sub	$5, %edi
	
	# %edi contiene l'indirizzo del salto corretto.
	# %esi contiene l'indirizzo dell'istruzione da correggere
	    
	movl	%edi, 1(%esi)		# La jump da correggere ha un opcode di un byte	
	
	
	    
	popfw				# Ripristina i registri e termina
	pop	%edi
	pop	%esi
	pop	%ebp
	add	$4, %esp
	pop	%ebx
	pop	%edx
	pop	%ecx
	pop	%eax
	ret
