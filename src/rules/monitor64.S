.file "monitor64.S"

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
	add	$32+16, %rax 		 # %rsp è salito di 4 posizioni rispetto all'inizio, in più hijacker ha inserito 16 byte prima della call
	mov	%rax, (%rsp)
	push	%rbp 			 # Salva i valori degli altri registri
	push	%rsi
	push	%rdi

	# TODO: salvare gli altri 8 registri general purpose

# OCCHIO CHE QUESTO DEVE ESSERE GESTITO DA HIJACKER NELLA GENERAZIONE DELLE ISTRUZIONI INTORNO ALLA CALL
#	pushfw				# salva il registro EFLAGS

	mov	%rsp, %rbp		# (12->24) Crea la finestra dello stack
	add	$64-8, %rbp 			# (4->8) %rbp deve puntare il valore di %rax nello stack

	# ???
#	mov	8(%rbp), %rsi		# (4->8) Carica il valore di ritorno della funzione chiamante in %rsi



	# Caricare dallo stack la struttura:
	# [DC] La struttura è stata caricata seguendo l'ordine naturale di espansione dello stack,
	# pertanto è sufficiente navigare incrementando lo stack pointer per ricostruire la struttura
	# dal primo campo.

	# In rdx verrà caricato l'indirizzo del primo campo della struttura
	# Attualmente rbp punta al valore rax salvato nello stack, ovvero una posizione avanti rispetto all'indirizzo
	# di ritorno e, quindi, due posizioni avanti rispetto al primo campo 'size' della struttura del monitor
	
	lea 16(%rbp), %rdx		# Sommo 16 byte a %rbp per farlo salire di 2 posizioni nello stack. %rdx rappresenta la base della struttura, ora

	# Carica il campo flags della row corrente:
	# Il campo 'flags' si trova prima del campo 'size', pertanto 4 byte a salire nello stack
	movsbq	4(%rdx), %rax		# Carica il campo 'flags' (4 byte) in %rax


	#Gestione delle MOVS e STOS
	#testb	$1, %al			# Una MOVS?
	#jz	.ScritturaNormale	# No...
	#movsbq insn_table+8(%rdx), %rsi	# Carica la dimensione del dato
	#   	imul	-8(%rbp), %rsi		#  (4->8) Carica dallo stack il valore originale di %rcx (numero di elementi) e lo moltiplica per la taglia
	#mov	-56(%rbp), %rdi 	#  (28->56) Recupera dallo stack il valore originale di EDI
	#pushfw				# Calcola il valore di Direction Flag
	#popw	%bx
	#bt	$10, %bx		# DF è EFLAGS[10]
	#jnc	.DF0			# DF = 0
	#sub	%rsi, %rdi		# DF = 1: %rdi viene decrementato. %rdi conteneva la *fine* dell'area di memoria scritta
	#.DF0: 				# Qui DF = 0: %rdi viene incrementato: %rdi contiene l'inizio della scrittura e non occorre fare nulla
	#jmp .CallDymelor


	.ScritturaNormale:
	xor	%rdi, %rdi			# %rdi conterrà l'indirizzo iniziale della scrittura
	testb	$4, %al 		# Controlla se c'è un registro indice
	jz	.NoIndex
	movsbq	6(%rdx), %rcx				# Carica in %rcx il valore dell'indice
	negq	%rcx
	movq	(%rbp, %rcx, 8), %rdi		# Salva il valore che era contenuto nel registro indice
	movsbq	7(%rdx), %rdi				# Recupera la scala in %rdi
	imul	%rcx, %rdi					# e la moltiplica per l'indice

	.NoIndex:
	testb	$2, %al 					# Controlla se c'è un registro di base
	jz	.NoBase
	movsbq 5(%rdx), %rcx				# Recupera la base dalla struttura
	negq	%rcx
	addq	(%rbp, %rcx, 8), %rdi		# Aggiunge il valore dell'indirizzo di base


	.NoBase:
	add		8(%rdx), %rdi				# Aggiunge l'offset
	movslq	(%rdx), %rsi				# Carica la dimensione

	.CallDymelor:
	# %rdi contiene l'indirizzo iniziale in cui la movs scriverà
	# %rsi contiene la dimensione (in byte) della movs

	# Controllo per vedere se siamo nello stack
	cmp 	%rdi, %rsp		# Nello stack?
	call	increment_stack_mov_count  # Chiama la funzione per il calcolo delle stack mov
	jb	.Fine				# Se %esp è minore di %edi

	# La calling convention del System V ABI prevede che vengano passati
	# per primi i registri %rdi e %rsi, in questa sequenza
	call	reverse_code_generator		# Chiama la funzione che si preoccupa della generazione del codice inverso


	.Fine:
#	popfw
	pop	%rdi 			# Ripristina i registri
	pop	%rsi
	pop	%rbp
	add	$8, %rsp		# (4->8)
 	pop	%rbx
 	pop	%rdx
 	pop	%rcx
	pop	%rax
	ret

.size   monitor, .-monitor
