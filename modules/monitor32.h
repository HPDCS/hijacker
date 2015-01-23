#ifndef _MONITOR32_H
#define _MONITOR32_H

/* Entry per la tabella delle istruzioni */
typedef struct {
	unsigned long ret_addr;	// L'indirizzo immediatamente successivo all'istruzione chiamante
	unsigned int size;	// Dimensione in byte della scrittura
	char flags;		// I flag riguardanti l'indirizzamento di quest'istruzione
	char base;		// Il valore della base (0x00 - 0x0f)
	char idx;		// Il valore dell'idx (0x00 - 0x0f)
	char scala;		// Scala dell'indice (0, 1, 2 o 4)
	long offset;		// Il displacement dell'istruzione
} insn_entry_32;

#endif

