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
* @file executable.h
* @brief Structures to map object files to internal representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
*/

#pragma once
#ifndef _EXECUTABLE_H
#define _EXECUTABLE_H

#include <elf/elf-defs.h>

#include <utils.h>
#include <instruction.h>
#include <rules.h>

typedef enum {BLOCK_SPLIT_FIRST, BLOCK_SPLIT_LAST} block_split_mode;

typedef struct _block {
  unsigned int id;
  unsigned long length;			// Number of instructions that make up the block

  insn_info *begin;         // First instruction of the block
  insn_info *end;           // Last instruction of the block
  struct _block *next;       // Ordered list of blocks

  // Flowgraph-related fields
  linked_list out;          // Double-linked list of next blocks
  linked_list in;           // Double-linked list of previous blocks

  // Tree-related fields
  int balance;              // The balance factor of the AVL tree rooted at this block
  unsigned int height;        // The height of the AVL tree rooted at this block
  struct _block *left;       // Left child in the AVL tree
  struct _block *right;      // Right child in the AVL tree
  struct _block *parent;     // Parent block in the AVL tree
} block;



#define SYMBOL_VARIABLE	1
#define SYMBOL_FUNCTION	2
#define SYMBOL_UNDEF	3
#define SYMBOL_SECTION	4
#define SYMBOL_FILE		5

#define SYMBOL_LOCAL	0
#define SYMBOL_GLOBAL	1
#define SYMBOL_WEAK		2

typedef struct _symbol {
	int 		type;			/// The hijacker's local type specification of the symbol
	int		bind;			/// The hijacker's local bind specification of the symbol
	unsigned char	*name;			/// Pointer to the buffer holding the symbol's name
	unsigned int	size;		/// Size of the symbol, could be zero (e.g. for SYMBOL_UNDEF)
	unsigned int	secnum;			/// Index of the section the symbol belongs to
	unsigned int	index;			/// Symbol's index within the symbol table
	unsigned long long	position;		/// Offset positioning within the symbol section
	unsigned long long	initial;		/// Initialization symbol's value
	struct _relocation {
//		struct _symbol *from;		/// Symbol from which the relocation applies
		insn_info *ref_insn;		/// Instruction where the relocation is applied
		long long offset;			/// The offset from the reference symbol's position
		long addend;				/// The offset from the target symbol
		unsigned char type;			/// The type of the relocation
		unsigned char *secname;		/// Name of the relocation section where to add the entry
	} relocation;
	int	version;	/// Integer indicasting to which instrumenting verions it belongs
	bool		duplicate;		/// Flag that tells if symbol is a duplicate
	bool		referenced;		/// Flag indicating the symbol has been resolved
	long		extra_flags;	/// Maintains the info field of the ELF's symbol (either bind and type) # ridondante
	struct _symbol	*next;
} symbol;


typedef struct _function {
  block *being_blk; // [SE]
  block *end_blk;   // [SE]
	int			passes;
	unsigned char		*name;
	unsigned long long	orig_addr;
	unsigned long long	new_addr;
	insn_info		*insn;
	symbol 			*symbol;	// [DC] Added reference to the relative symbol
	struct _function *next;
} function;


typedef struct _reloc {
	long long offset;
	unsigned char *name;
	symbol *symbol;
	unsigned int s_index;
	int type;
	int addend;
	struct _reloc	*next;
} reloc;



#define SECTION_CODE 	1
#define SECTION_SYMBOLS	2
#define SECTION_NAMES	3
#define SECTION_RELOC	4
#define SECTION_RAW		5

typedef struct _section {
	int		type;
	unsigned int	index;
	unsigned char	*name;
	void		*header;
	void		*payload;
	void		*ptr;		// [DC] Payoad's file pointer (emit stage)
	void 		*reference;	// [DC] May represent a reference to a relocation entry (emit stage)
	struct _section	*next;
} section;



#define EXECUTABLE_ELF	1

#define MAX_VERSIONS	256

typedef struct _executable {
	int type;
	int insn_set;
	union {
		elf_file	elf;
	} e;
	symbol		*orig_syms;
	function	*v_code[MAX_VERSIONS];
	unsigned int	version;	/// Current instrumenting version
	unsigned int	versions;	/// Number of total versions
	void 		*metadata;
	unsigned int	symnum;
	symbol		*symbols;
	unsigned int	secnum;
	section		*sections;
	function	*code;		// [DC] Added this field to handle the parsed functions
	void 	*rawdata;		// [DC] Added this filed to handle preallocated raw data
	block *blocks;		// [SE] Basic block overlay
} executable_info;


extern void update_instruction_addresses(void);
extern void update_jump_displacements(void);

extern void set_jumpto_reference(insn_info *jump, insn_info *target);
extern void set_jumptable_entry(insn_info *jump, insn_info *entry, unsigned int idx);
extern void set_virtual_reference(insn_info *target, insn_info *virtual);



//extern void add_section(int type, void *header, void *payload);
extern void add_section(int type, int secndx, void *payload);
extern section *get_section_type(int type);
extern void load_program(char *path);
extern void output_object_file(char *pathname);

extern block *block_create(void);
extern block *block_split(block *node, insn_info *breakpoint, block_split_mode mode);
extern block *block_find(insn_info *instr);
extern void block_link(block *from, block *to);
extern void block_tree_dump(char *filename);
extern void block_graph_dump(block *start, char *filename);

#endif /* _EXECUTABLE_H */

