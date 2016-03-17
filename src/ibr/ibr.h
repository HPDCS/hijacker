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
*   Executable and executable versions
************************************************************/

typedef enum {
	ELF,
	COFF,
	MACHO
} obj_format_t;


typedef enum {
	IA32,
	AMD64,
	// ARM,
	// ARM64
} isa_family_t;


#define MAX_VERSIONS 256


struct object {
	obj_format_t format;            /// The object file format type (e.g. ELF)
	isa_family_t arch;              /// The ISA language of the machine code (e.g. x86-64)

	ver_t *versions[MAX_VERSIONS];  /// Array of object file versions
	ver_t *cversion;                /// The current object file version
	size_t nversion;                /// The total number of existing versions
};


struct version {
	unsigned long number;           /// The version number ID
	const char *name;               /// The name of this version

	struct {                        /// All sections specific for this version
		sec_t *first;
		sec_t *last;
	} sections;

	struct {                        /// All symbols specific for this version
		sym_t *first;
		sym_t *last;
	} symbols;

	struct {                        /// All relocs specific for this version
		rel_t *first;
		rel_t *last;
	} relocs;

	struct {                        /// The functions that make up this version's code
		fun_t *first;
		fun_t *last;
	} functions;

	struct {                        /// The blocks that make up this version's code
		blk_t *first;
		blk_t *last;
	} blocks;

	struct {                        /// The instructions that make up this version's code
		isn_t *first;
		isn_t *last;
	} instructions;

	graph_t /* <fun_t> */ fcg;      /// The Function Call Graph of this version
};


#define foreach_version(version, number) \
	for (number = 0, version = PROGRAM(versions)[number]; \
	     number < PROGRAM(nversion); number += 1)


#define foreach_section(section) \
	for (section = VERSION(sections).first; section; section = section->next)


#define foreach_symbol(symbol) \
	for (symbol = VERSION(symbols).first; symbol; symbol = symbol->next)


#define foreach_reloc(reloc) \
	for (reloc = VERSION(relocs).first; reloc; reloc = reloc->next)


#define foreach_function(function) \
	for (function = VERSION(functions).first; function; function = function->next)


#define foreach_block(block) \
	for (block = VERSION(blocks).first; block; block = block->next)


#define foreach_instr(instr) \
	for (instr = VERSION(instructions).first; instr; instr = instr->next)


obj_t *executable_load(const char *path);


void executable_write(const char *path);


ver_t *version_create(const char *name);


ver_t *version_switch(unsigned long number);


/************************************************************
*   Sections, symbols and relocations
************************************************************/

// FIXME: Incomplete list
typedef enum {
	SECTION_NULL,
	SECTION_CODE,
	SECTION_SYMBOLS,
	SECTION_NAMES,
	SECTION_RELOC,
	SECTION_TLS,
	SECTION_RAW
} sec_type_t;


extern const char *sec_type_str[];


struct section {
	sym_t *symbol;                  /// The symbol representing this section

	sec_type_t type;                /// DATA, CODE, RELOC, DEBUG, etc...
	unsigned long flags;            /// ALLOC, LOAD, READ, WRITE, etc...

	void *payload;                  /// Section contents

	// An instruction chain is maintained for each object file version
	sec_t *next;                    /// Previous section in the chain
	sec_t *prev;                    /// Next section in the chain
};


// FIXME: Incomplete list
typedef enum {
	SYMBOL_NULL,
	SYMBOL_VARIABLE,
	SYMBOL_FUNCTION,
	SYMBOL_UNDEF,
	SYMBOL_SECTION,
	SYMBOL_FILE,
	SYMBOL_TLS
} sym_type_t;


extern const char *sym_type_str[];


struct symbol {
	unsigned long id;               /// The unique id of this symbol
	const char *name;               /// The name of this symbol

	sym_type_t type;                /// FUNCTION, OBJECT, etc...
	unsigned long flags;            /// LOCAL, GLOBAL, WEAK, etc...

	void *payload;                  /// Symbol contents
	size_t size;                    /// The size of this symbol

	union {                         /// What the symbol represents...
		fun_t *function;              /// ...a function
		sec_t *section;               /// ...a section
	} is;

	union {                         /// Relocations associated to this symbol...
		list_t /* <rel_t> */ source;  /// ...when the symbol owns the relocation
		list_t /* <rel_t> */ dest;    /// ...when the relocation refers to the symbol
	} rel;

	sec_t *sec;                     /// The section that contains this symbol
	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which the symbol contents can be found

	// An instruction chain is maintained for each object file version
	sym_t *next;                    /// Previous symbol in the chain
	sym_t *prev;                    /// Next symbol in the chain
};


// FIXME: Incomplete list
typedef enum {
	RELOC_PCREL_32,
	RELOC_PCREL_64,
	RELOC_TLSREL_32,
	RELOC_ABS_32,
	RELOC_ABS_32S,
	RELOC_ABS_64,
} rel_type_t;


extern const char *rel_type_str[];


struct relocation {
	rel_type_t type;                /// ABSOLUTE, RELATIVE, etc...

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

	// An instruction chain is maintained for each object file version
	rel_t *next;                    /// Previous relocation in the chain
	rel_t *prev;                    /// Next relocation in the chain
};


sec_t *section_insert(const char *name, sec_type_t type,
                      unsigned long flags, void *payload);


void section_remove(sec_t *section);


// sec_t *section_find(sec_t *match);


// sec_t *section_find_byname(const char *name);


sym_t *symbol_insert(const char *name, sym_type_t type,
                     unsigned long flags, void *payload);


void symbol_remove(sym_t *symbol);


// sym_t *symbol_find(sym_t *match);


// sym_t *symbol_find_byname(const char *name);


rel_t *reloc_create(rel_type_t type, sec_t *section, addr_t offset,
                    sym_t *symbol, off_t addend);


rel_t *reloc_isn_to_sym(rel_type_t type, isn_t *instr,
                        sym_t *symbol, off_t addend);

rel_t *reloc_sec_to_isn(rel_type_t type, sec_t *section, addr_t offset,
                        isn_t *instr);


/************************************************************
*   Functions, blocks and instructions
************************************************************/

struct function {
	sym_t *symbol;                  /// The symbol representing this function

	graph_t /* <blk_t> */ cfg;      /// The CFG of this function

	blk_t *begin_block;             /// The first block of this function
	blk_t *end_block;               /// The last block of this function

	// A function chain is maintained for each object file version
	fun_t *prev;                    /// Previous function in the chain
	fun_t *next;                    /// Next function in the chain
};


typedef enum {
	BLOCK_GENERIC,
	BLOCK_LOOP_HEADER,
	BLOCK_LOOP_FOOTER,
	BLOCK_BRANCH_HEADER,
	BLOCK_BRANCH_THEN,
	BLOCK_BRANCH_ELSE
} blk_type_t;


extern const char *blk_type_str[];


typedef enum {
	EDGE_GOTO,
	EDGE_THEN,
	EDGE_ELSE,
	EDGE_FORCED,
	EDGE_IND,
	EDGE_CALLRET,
	EDGE_INIT
} blk_edge_type_t;


typedef enum {
	EDGE_NEXT,
	EDGE_BACK
} blk_edge_dir_t;


// typedef enum {
// 	SPLIT_FIRST,
// 	SPLIT_LAST
// } blk_split_mode_t;


struct block {
	blk_type_t type;                /// LOOP HEADER, LOOP FOOTER, etc...

	isn_t *begin_instr;             /// The first instruction of this block
	isn_t *end_instr;               /// The last instruction of this block

	// Presets-related fields
	void *smtracer;

	size_t length;                  /// The number of instructions that make up this block

	// An instruction chain is maintained for each object file version
	blk_t *next;                    /// Previous block in the chain
	blk_t *prev;                    /// Next block in the chain
};


typedef enum {
	INSTR_MNEMONIC,
	INSTR_RAWBYTES,
} isn_input_type_t;


typedef enum {
	INSERT_BEFORE,
	INSERT_AFTER,
} isn_insert_mode_t;


struct instruction {
	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which this instruction can be found

	// Architecture-independent information
	unsigned char mnemonic[32];     /// Textual representation of the instruction
	unsigned char instruction[32];  /// Raw bytes of the instruction
	unsigned long long flags;       /// MEMORY, ALGEBRIC, LOGIC, STACK, etc...
	unsigned int length;            /// Length in bytes

	union {                         /// Architecture-specific information
		// isn_info_specific_x86 x86;
		// isn_info_specific_arm arm;
	} arch;

	struct {                        /// Jump-table for this instruction
		size_t fanout;                /// Number of detected destinations
		list_t /* <isn_t> */ instr;   /// List of detected destination instructions
	} to;

	struct {                        /// Inverse jump-table for this instruction
		size_t fanin;                 /// Number of detected sources
		list_t /* <isn_t> */ instr;   /// List of detected source instructions
	} from;

	union {                         /// Relocations associated to this instruction...
		list_t /* <rel_t> */ source;  /// ...when the instruction owns the relocation
		list_t /* <rel_t> */ dest;    /// ...when the relocation refers to the instruction
	} rel;

	// An instruction chain is maintained for each object file version
	isn_t *prev;                    /// Previous instruction in the chain
	isn_t *next;                    /// Next instruction in the chain
};


#define foreach_function_block(function, block) \
	for (block = function->begin_block; \
	     block != function->end_block->next; \
	     block = block->next)


#define foreach_function_instr(function, instr) \
	for (instr = function->begin_block->begin_instr; \
	     instr != function->end_block->end->instr->next; \
	     instr = instr->next)


#define foreach_block_instr(block, instr) \
	for (instr = block->begin_instr; \
	     instr != block->end_instr->next; \
	     instr = instr->next)


fun_t *function_create(const char *name, isn_t *begin, isn_t *end);


void function_remove(fun_t *function);


// fun_t *function_find(fun_t *match);


// fun_t *function_find_byname(const char *name);


// fun_t *function_find_byblock(blk_t *block);


// fun_t *function_find_byinstr(isn_t *instr);


// blk_t *block_find_byinstr(isn_t *instr);


isn_t *instr_insert(const unsigned char *input, isn_input_type_t type,
                    isn_t *pivot, isn_insert_mode_t where);


void instr_remove(isn_t *from, isn_t *to);


#endif /* _IBR_H */
