#pragma once
#ifndef _INSTRUCTION_X86_H
#define _INSTRUCTION_X86_H


/// Data fields in instructions are 32-bits
#define	DATA_32 0x01
/// Address fields in instructions are 32-bits
#define	ADDR_32 0x02
/// Data fields in instructions are 64-bits
#define	DATA_64 0x04
/// Address fields in instructions are 64-bits
#define	ADDR_64 0x08


typedef struct insn_info_x86 {
	unsigned long flags;		// Insieme di flags contenente informazioni utili generiche riguardo l'istruzione
	unsigned char insn[15];		// I byte dell'istruzione (15 è il limite massimo)
	unsigned char opcode[2];	// L'opcode dell'istruzione
	char mnemonic[8];		// Il nome dell'istruzione
	unsigned long initial;		// Posizione iniziale nel testo
	unsigned long insn_size;	// Lunghezza dell'istruzione
	unsigned long addr;		// Indirizzo puntato dall'istruzione, o 0x00
	unsigned long span;		// Quanto in memoria verrà riscritto/letto, o 0x00
	bool has_index_register;	// L'indirizzamento sfrutta un indice?
	unsigned char ireg;		// Quale registro contiene l'indice?
	char ireg_mnem[8];		// Mnemonico del registro di indice
	bool has_base_register;		// L'indirizzamento sfrutta una base?
	unsigned char breg;		// Quale registro contiene la base?
	char breg_mnem[8];		// Mnemonico del registro
	bool has_scale;			// L'indirizzamento utilizza una scala
	unsigned long scale;		// La scala
	unsigned long disp_offset;	// Lo spiazzamento del displacement dall'inizio del testo
	unsigned long long disp;	// Il valore dello spiazzamento
	unsigned int opcode_size;	// [DC] Dimensione dell'opcode per l'istruzione
	int32_t jump_dest;		// Dove punta la jmp
	bool uses_rip;
} insn_info_x86;

extern void x86_disassemble_instruction (unsigned char *text, unsigned long *pos, insn_info_x86 *instrument, char flags);

#endif /* _INSTRUCTION_X86_H */

