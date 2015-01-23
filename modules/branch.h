#ifndef _BRANCH_H
#define _BRANCH_H

struct _off_row {
  unsigned long whence;		// Whence to apply this shift correction
  unsigned long how_much;	// How much to correct
};

typedef struct _off_row off_row, off_table;

/* Entry per la tabella delle istruzioni */
struct _branch_insn{
	unsigned long ret_addr;	// L'indirizzo immediatamente successivo all'istruzione chiamante
	char flags;		// I flag riguardanti l'indirizzamento di quest'istruzione
	char base;		// Il valore della base (0x00 - 0x0f)
	char idx;		// Il valore dell'idx (0x00 - 0x0f)
	char scala;		// Scala dell'indice (0, 1, 2 o 4)
	long offset;		// Il displacement dell'istruzione
};

typedef struct _branch_insn branch_insn, branch_table;

#endif /* _BRANCH_H */
