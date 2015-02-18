#pragma once
#ifndef _INSTRUCTIONS_H
#define _INSTRUCTIONS_H


#include <alpha/instruction.h>
#include <arm/instruction.h>
#include <ia_64/instruction.h>
#include <mips/instruction.h>
#include <powerpc/instruction.h>
#include <sparc/instruction.h>
#include <x86/instruction.h>

#include <executable.h>

// [FV] Flags contenenti informazioni utili sul comportamento o la classe delle funzioni
#define I_MEMRD		0x1	// Legge dalla memoria
#define I_MEMWR		0x2	// Scrive sulla memoria
#define I_CTRL 		0x4	// Istruzioni della famiglia "test" e "control" che controllano valori di dati o singoli bit
#define I_JUMP 		0x8	// Istruzioni della famiglia "jump", che modificano il flusso di esecuzione del processore
#define I_CALL	 	0x10	// Istruzione del tipo "call"
#define I_RET 		0x20	// Istruzione del tipo "call"
#define I_CONDITIONAL	0x40	// Istruzione che viene eseguite se e solo se e' soddisfatta una condizione
#define I_STRING	0x80	// Opera su stringhe (e.g. movs, stos, cmps...)
#define I_ALU		0x100	// Esegue operazioni di tipo logico-aritmetico
#define I_FPU		0x200	// Utilizza la Floating Point Unit (FPU)
#define I_MMX		0x400	// Istruzione che utilizza i registri MMX
#define I_XMM		0x800	// Istruzione che utilizza i registri XMM
#define I_SSE		0x1000	// Istruzione SSE
#define I_SSE2		0x2000	// Istruzione SSE2
#define I_PUSHPOP	0x4000	// Istruzione di tipo "push" o di tipo "pop"
#define I_STACK		0x8000	// Se l'istruzione opera nello stack
#define I_JUMPIND	0x10000	// Indirect Branch


// [FV] Macro per il testing dei flags
#define IS_MEMRD(X)		((X)->flags & I_MEMRD)
#define IS_MEMWR(X)		((X)->flags & I_MEMWR)
#define IS_CTRL(X)		((X)->flags & I_CTRL)
#define IS_JUMP(X)		((X)->flags & I_JUMP)
#define IS_JUMPIND(X)		((X)->flags & I_JUMPIND)
#define IS_CALL(X)		((X)->flags & I_CALL)
#define IS_RET(X)		((X)->flags & I_RET)
#define IS_CONDITIONAL(X)	((X)->flags & I_CONDITIONAL)
#define IS_STRING(X)		((X)->flags & I_STRING)
#define IS_ALU(X)		((X)->flags & I_ALU)
#define IS_FPU(X)		((X)->flags & I_FPU)
#define IS_MMX(X)		((X)->flags & I_MMX)
#define IS_XMM(X)		((X)->flags & I_XMM)
#define IS_SSE(X)		((X)->flags & I_SSE)
#define IS_SSE2(X)		((X)->flags & I_SSE2)
#define IS_PUSHPOP(X)		((X)->flags & I_PUSHPOP)
#define IS_STACK(X)		((X)->flags & I_STACK)


// Strings to load macros from the configuration file
#define I_MEMRD_S	"I_MEMRD"
#define I_MEMWR_S	"I_MEMWR"
#define I_CTRL_S	"I_CTRL"
#define I_JUMP_S	"I_JUMP"
#define I_JUMPIND_S	"I_JUMPIND"
#define I_CALL_S	"I_CALL"
#define I_RET_S		"I_RET"
#define I_CONDITIONAL_S	"I_CONDITIONAL"
#define I_STRING_S	"I_STRING"
#define I_ALU_S		"I_ALU"
#define I_FPU_S		"I_FPU"
#define I_MMX_S		"I_MMX"
#define I_XMM_S		"I_XMM"
#define I_SSE_S		"I_SSE"
#define I_SSE2_S	"I_SSE2"
#define I_PUSHPOP_S	"I_PUSHPOP"
#define I_STACK_S	"I_STACK"


// Arch-Dependent Instruction Sets
#define UNRECOG_INSN	0
#define ALPHA_INSN	1
#define ARM_INSN	2
#define IA_64_INSN	3
#define MIPS_INSN	4
#define POWERPC_INSN	5
#define SPARC_INSN	6
#define X86_INSN	7


typedef struct instruction {
	unsigned long		flags;
	unsigned long long	orig_addr;
	unsigned long long	new_addr;
	unsigned int		size;
	unsigned int		opcode_size;	// [DC] To keep trace of the opcode size
	union {
		insn_info_alpha		alpha;
		insn_info_arm		arm;
		insn_info_ia_64		ia_64;
		insn_info_mips		mips;
		insn_info_powerpc	powerpc;
		insn_info_sparc		sparc;
		insn_info_x86		x86;
	} i;
	//void *reference;			// May represent a reference to either a relocation symbol or an instruction (jump)
	struct instruction *jumpto;
	struct _symbol *reference;
	struct instruction *prev;	// Instructions are organized in a chain
	struct instruction *next;
} insn_info;

#endif /* _INSTRUCTIONS_H */
