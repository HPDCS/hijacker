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
* @file ibr.h
* @brief Structures to map object files to Hijacker's Intermediate Binary Representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
*/

#pragma once
#ifndef _IBR_H
#define _IBR_H

#include <init.h>
#include <structs.h>


typedef struct object      obj_t;
typedef struct version     ver_t;
typedef struct section     sec_t;
typedef struct symbol      sym_t;
typedef struct relocation  rel_t;
typedef struct function    fun_t;
typedef struct block       blk_t;
typedef struct instruction isn_t;


/************************************************************
*   Object file and object file versions
************************************************************/

typedef enum {
	ELF,
	COFF,
	MACHO
} obj_format_t;


typedef enum {
	X86,
	X86_64,
	// ARM,
	// ARM64
} isa_family_t;


#define MAX_VERSIONS 256


struct object {
	obj_format_t format;            /// The object file format type (e.g. ELF)
	isa_family_t arch;              /// The ISA language of the machine code (e.g. x86-64)

	ver_t *version;                 /// The current object file version
	ver_t *versions[MAX_VERSIONS];  /// Array of object file versions
	size_t nversions;               /// The total number of existing versions
};


struct version {
	unsigned long number;           /// The version number ID
	const char *name;               /// The name of this version

	list_t sections;                /// All sections specific for this version
	list_t symbols;                 /// All symbols specific for this version
	list_t relocs;                  /// All relocations specific for this version
	list_t functions;               /// The functions that make up this version's code
	list_t blocks;                  /// The blocks that make up this version's code
	list_t instructions;            /// The instructions that make up this version's code

	graph_t fcg;                    /// The Function Call Graph of this version
};


#define foreach_version(version, number)\
	for (number = 0, version = __PROGRAM__(versions)[number];\
	     number < __PROGRAM__(nversions); number += 1)


obj_t *executable_load(const char *path);


void executable_write(const char *path);


ver_t *version_create(const char *name);


ver_t *version_switch(unsigned long number);


/************************************************************
*   Low-level IBR: Sections, symbols and relocations
************************************************************/

// typedef enum {
// 	SECTION_NULL,
// 	SECTION_CODE,
// 	SECTION_SYMBOLS,
// 	SECTION_NAMES,
// 	SECTION_RELOC,
// 	SECTION_TLS,
// 	SECTION_RAW
// } sec_type_t;


struct section {
	sym_t *symbol;                  /// The symbol representing this section

	unsigned long type;             /// DATA, CODE, RELOC, DEBUG, etc...
	unsigned long flags;            /// ALLOC, LOAD, READ, WRITE, etc...

	// FIXME: In principle, this could as well be a struct
	union {                         /// What the section contains...
		list_range_t symbols;         /// ...a list of addressable symbols
		list_range_t relocs;          /// ...a list of relocations
		list_range_t functions;       /// ...a list of functions
	} has;

	list_t relocs;                  /// List of relocations that apply to this section

	// union {                        /// Balanced search tree index of...
	// 	bst_t symbols;                /// ...symbols
	// 	bst_t relocs;                 /// ...relocations
	// 	bst_t functions;              /// ...blocks
	// } index;

	list_node_t *node;              /// Associated node in the per-version section list
};


// typedef enum {
// 	SYMBOL_NULL,
// 	SYMBOL_VARIABLE,
// 	SYMBOL_FUNCTION,
// 	SYMBOL_UNDEF,
// 	SYMBOL_SECTION,
// 	SYMBOL_FILE,
// 	SYMBOL_TLS
// } sym_type_t;


struct symbol {
	unsigned long id;               /// The unique id of this symbol
	const char *name;               /// The name of this symbol

	unsigned long type;             /// FUNCTION, OBJECT, etc...
	unsigned long flags;            /// LOCAL, GLOBAL, WEAK, etc...

	// TODO: Could be a displacement from the pointer of section->payload!
	unsigned char *bytes;           /// Raw symbol payload
	size_t size;                    /// The size of this symbol in bytes

	sec_t *section;                 /// The section that contains this symbol
	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which the symbol contents can be found

	union {                         /// What the symbol represents...
		fun_t *function;              /// ...a function
		sec_t *section;               /// ...a section
		// dat_t *data;                  /// ...some data
	} isa;

	list_range_t *relocs;           /// List of relocations that refer to this symbol

	list_node_t *node;              /// Associated node in the per-version symbol list
};


// typedef enum {
// 	RELOC_PCREL_32,
// 	RELOC_PCREL_64,
// 	RELOC_TLSREL_32,
// 	RELOC_ABS_32,
// 	RELOC_ABS_32S,
// 	RELOC_ABS_64,
// } rel_type_t;


struct relocation {
	unsigned long type;             /// ABSOLUTE, RELATIVE, etc...

	struct {                        /// Relocation found...
		sec_t *section;               /// ...in this section
		addr_t offset;                /// ...at this offset
		isn_t *instr;                 /// ...(in this instruction)
	} in;

	struct {                        /// Relocation referring...
		sym_t *symbol;                /// ...to this symbol
		off_t addend;                 /// ...at this displacement
		isn_t *instr;                 /// ...(to this instruction)
	} to;

	list_node_t *node;
};


sec_t *section_insert(const char *name, unsigned long type, unsigned long flags,
                      void *payload, sym_t *symbol);


void *section_remove(sec_t *section);


sec_t *section_find_byname(const char *name);


sym_t *symbol_insert(const char *name, unsigned long type, unsigned long flags,
                     sec_t *section, unsigned char *bytes);


void *symbol_remove(sym_t *symbol);


sym_t *symbol_find_byname(const char *name);


sym_t *symbol_find_byaddr(addr_t address, sec_t *section);


rel_t *reloc_insert(unsigned long type, sec_t *section, addr_t offset,
                    sym_t *symbol, off_t addend);


rel_t *reloc_isn_to_sym(unsigned long type, isn_t *instr,
                        sym_t *symbol, off_t addend);


rel_t *reloc_sec_to_isn(unsigned long type, sec_t *section, addr_t offset,
                        isn_t *instr);


rel_t *reloc_remove(rel_t *reloc);


rel_t *reloc_find_bysymbol(sym_t *symbol, sec_t *section);


/************************************************************
*   High-level IBR: Functions, blocks and instructions
************************************************************/

typedef enum {
	EDGE_CALL_STRONG,
	EDGE_CALL_WEAK,
	EDGE_CALL_HANDLER
} fcg_edge_label;


struct function {
	sym_t *symbol;                  /// The symbol representing this function

	size_t length;                  /// The number of blocks that make up this function
	list_range_t blocks;            /// The range of blocks that make up this function
	graph_t cfg;                    /// The CFG of this function

	// struct {
	// 	bst_t blocks;
	// } index;

	graph_node_t *fcgnode;          /// The FCG node in the parent object file version
	list_node_t *node;
};


typedef enum {
	NODE_GENERIC,
	NODE_LOOP_HEADER,
	NODE_LOOP_FOOTER,
	NODE_BRANCH_HEADER,
	NODE_BRANCH_THEN,
	NODE_BRANCH_ELSE
} cfg_node_label;


typedef enum {
	EDGE_GOTO,
	EDGE_THEN,
	EDGE_ELSE,
	EDGE_FORCED,
	EDGE_IND,
	EDGE_CALLRET,
	EDGE_INIT
} cfg_edge_label;


typedef enum {
	EDGE_NEXT,
	EDGE_BACK
} cfg_edge_dir;


typedef enum {
	SPLIT_FIRST,
	SPLIT_LAST
} blk_split_mode;


struct block {
	fun_t *function;

	cfg_node_label label;           /// LOOP HEADER, LOOP FOOTER, etc...

	size_t length;                  /// The number of instructions that make up this block
	list_range_t instructions;      /// The range of instructions that make up this block

	graph_node_t *cfgnode;          /// The CFG node in the parent function
	list_node_t *node;
};


typedef enum {
	INSTR_MNEMONIC,
	INSTR_RAWBYTES,
} isn_input_type;


struct instruction {
	blk_t *block;
	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which this instruction can be found

	unsigned long type;             /// MEMORY, ALGEBRIC, LOGIC, STACK, etc...
	size_t length;                  /// Length in bytes

	char mnemonic[32];              /// Textual representation of the instruction
	unsigned char bytes[32];        /// Raw bytes of the instruction

	// union {                         /// Architecture-specific information
	// 	isn_specific_x86 x86;
	// 	isn_specific_arm arm;
	// } arch;

	union {                         /// Reachable destinations...
		list_t jumptable;             /// ...if the instruction is a jump
		list_t calltable;             /// ...if the instruction is a call
	} to;

	struct {                        /// Reachable sources...
		list_t jumptable;             /// ...which are jump instructions
		list_t calltable;             /// ...which are call instructions
	} from;

	union {                         /// Relocations associated to this instruction...
		list_t in;                    /// ...when the relocation applies to the instruction
		list_t to;                    /// ...when the relocation refers to the instruction
	} rel;

	list_node_t *node;
};


fun_t *function_insert(const char *name, list_range_t instructions,
                       sec_t *section, sym_t *symbol);


void function_remove(fun_t *function);


fun_t *function_find_byaddr(addr_t address, sec_t *section);


fun_t *function_find_byname(const char *name);


blk_t *block_find_byaddr(addr_t address, fun_t *function);


list_range_t instr_insert(const unsigned char *input, isn_input_type type,
                          isn_t *pivot, list_insert_mode mode);


void instr_remove(list_range_t instructions);


list_range_t instr_replace(const unsigned char *input, isn_input_type type,
                           list_range_t instructions);


isn_t *instr_find_byaddr(addr_t address, fun_t *function);


#define foreach_function_block(function, node)\
	for (node = function_first_block(function)->node;\
	     node != function_last_block(function)->node->next;\
	     node = node->next) \


#define foreach_block_instr(function, node)\
	for (node = block_first_instr(function)->node;\
	     node != block_last_instr(function)->node->next;\
	     node = node->next)


#define foreach_function_instr(function, node)\
	for (node = function_first_instr(function)->node;\
	     node != function_last_instr(function)->node->next;\
	     node = node->next)


__strong_inline__ blk_t *function_first_block(fun_t *function) {
	if (function == NULL || !range_valid(function->blocks)) {
		hinternal();
	}

	return function->blocks.first->elem;
}


__strong_inline__ blk_t *function_last_block(fun_t *function) {
	if (function == NULL || !range_valid(function->blocks)) {
		hinternal();
	}

	return function->blocks.first->elem;
}


__strong_inline__ isn_t *block_first_instr(blk_t *block) {
	if (block == NULL || !range_valid(block->instructions)) {
		hinternal();
	}

	return block->instructions.first->elem;
}


__strong_inline__ isn_t *block_last_instr(blk_t *block) {
	if (block == NULL || !range_valid(block->instructions)) {
		hinternal();
	}

	return block->instructions.last->elem;
}


__strong_inline__ isn_t *function_first_instr(fun_t *function) {
	return block_first_instr(function_first_block(function));
}


__strong_inline__ isn_t *function_last_instr(fun_t *function) {
	return block_last_instr(function_last_block(function));
}


__strong_inline__ fun_t *function_find_byinstr(isn_t *instr, sec_t *section) {
	if (instr == NULL) {
		hinternal();
	}

	// TODO: instr->block->function

	return function_find_byaddr(instr->offset, section);
}


__strong_inline__ blk_t *block_find_byinstr(isn_t *instr, fun_t *function) {
	if (instr == NULL) {
		hinternal();
	}

	// TODO: instr->block

	return block_find_byaddr(instr->offset, function);
}


#endif /* _IBR_H */
