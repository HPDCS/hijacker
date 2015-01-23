#pragma once
#ifndef _MONITOR64_H
#define _MONITOR64_H

/* Flag inseriti dal parser nella tabella */
#define MOVS		0x01
#define BASE		0x02
#define	IDX		0x04

/* Test sui flag */
#define is_movs(f) 		((f) & MOVS)
#define has_base(f)		((f) & BASE)
#define has_idx(f)		((f) & IDX)


/* Entry per la tabella delle istruzioni */
typedef struct {
	unsigned int size;		// Dimensione in byte della scrittura
	char flags;			// I flag riguardanti l'indirizzamento di quest'istruzione
	char base;			// Il valore della base (0x00 - 0x0f)
	char idx;			// Il valore dell'idx (0x00 - 0x0f)
	char scala;			// Scala dell'indice (0, 1, 2 o 4)
	long long offset;		// Il displacement dell'istruzione
} insn_entry;

#endif

