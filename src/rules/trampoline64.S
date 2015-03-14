/**
*                       Copyright (C) 2008-2015 HPDCS Group
*                       http://www.dis.uniroma1.it/~hpdcs
*
*
* This file is part of the Hijacker static binary instrumentation tool.
*
* Hijacker is free software; you can redistribute it and/or modify it under the
* terms of the GNU General Public License as published by the Free Software
* Foundation; either version 3 of the License, or (at your option) any later
* version.
*
* Hijacker is distributed in the hope that it will be useful, but WITHOUT ANY
* WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
* A PARTICULAR PURPOSE. See the GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along with
* hijacker; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*
* @file trampoline64.S
* @brief Module to determine at runtime the memory destination address and
* 	 call a specified function - x86_64 version
* @author Alessandro Pellegrini
* @author Roberto Vitali
* @author Davide Cingolani
*/

.file "trampoline64.S"

.text
.globl	trampoline
.type	trampoline, @function
trampoline:

# ESISTE L'ISTRUZIONE PUSHAD che mette nello stack i registri esattamente in quest'ordine.......

	push	%rax			 # Salva %rax nello stack
	push	%rcx 			 # Salva i registri nell'ordine di codice numerico usato dall'IS
	push	%rdx
	push	%rbx
	mov	%rsp, %rax 		 # Ricostruisce il valore iniziale di %rsp
	sub	$8, %rsp		 # Anzichè 4 toglie 8 a rsp (sale di una posizione nello stack)
	add	$64, %rax 		 # %rsp è salito di 4 posizioni rispetto all'inizio (5, con l'indirizzo di ritorno), in più hijacker ha inserito 24 byte prima della call
	mov	%rax, (%rsp)
	push	%rbp 			 # Salva i valori degli altri registri
	push	%rsi
	push	%rdi
	
	push	%r8
	push	%r9
	push	%r10
	push	%r11
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	# TODO: salvare gli altri 8 registri general purpose

# OCCHIO CHE QUESTO DEVE ESSERE GESTITO DA HIJACKER NELLA GENERAZIONE DELLE ISTRUZIONI INTORNO ALLA CALL
#	pushfw				# salva il registro EFLAGS

	mov	%rsp, %rbp		# (12->24) Crea la finestra dello stack
	add	$120, %rbp		# (4->8) %rbp deve puntare il valore di %rax nello stack

	# ???
#	mov	8(%rbp), %rsi		# (4->8) Carica il valore di ritorno della funzione chiamante in %rsi



	# Caricare dallo stack la struttura:
	# [DC] La struttura è stata caricata seguendo l'ordine naturale di espansione dello stack,
	# pertanto è sufficiente navigare incrementando lo stack pointer per ricostruire la struttura
	# dal primo campo.

	# In rdx verrà caricato l'indirizzo del primo campo della struttura
	# Attualmente rbp punta al valore rax salvato nello stack, ovvero una posizione avanti rispetto all'indirizzo
	# di ritorno e, quindi, due posizioni avanti rispetto al primo campo 'size' della struttura del trampoline
	
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
	# TODO: per il controllo nelo stack è necessario un controllo più sofisticato
	# che tenga conto del multi-threading. (Generalmente pthread alloca con malloc!)

	#call	increment_stack_mov_count  # Chiama la funzione per il calcolo delle stack mov
	
	#cmp 	%rdi, %rsp		# Nello stack?
	jb	.Fine				# Se %esp è minore di %edi

	# La calling convention del System V ABI prevede che vengano passati
	# per primi i registri %rdi e %rsi, in questa sequenza
	# call	reverse_code_generator		# Chiama la funzione che si preoccupa della generazione del codice inverso
	call *16(%rdx)			# Chiama la funzione specificata nelle regole XML, contenuta nell'ultimo campo della struttura di trampoline


	.Fine:
#	popfw
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%r11
	pop	%r10
	pop	%r9
	pop	%r8
	
	pop	%rdi 			# Ripristina i registri
	pop	%rsi
	pop	%rbp
	add	$8, %rsp		# (4->8)
 	pop	%rbx
 	pop	%rdx
 	pop	%rcx
	pop	%rax
	
	ret

.size   trampoline, .-trampoline
