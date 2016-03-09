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
typedef struct instruction ins_t;


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
	ARM,
	ARM64
} isa_family_t;


#define MAX_VERSIONS 256


struct object {
	obj_format_t format;            /// The object file format type (e.g. ELF)
	isa_family_t family;            /// The ISA language of the machine code (e.g. x86-64)

	list_t /* <sec_t> */ sections;  /// All sections in the program
	list_t /* <sym_t> */ symbols;   /// All symbols in the program
	list_t /* <rel_t> */ relocs;    /// All symbol references in the program

	ver_t *versions[MAX_VERSIONS];  /// One entry for each instrumented version
	                                /// of the object file

	size_t cversion;                /// The current version number
	size_t nversion;                /// The total number of existing versions
};


struct version {
	size_t number;                  /// The version number
	const char *name;               /// The name of this version

	list_t /* <sec_t> */ sections;  /// All sections specific for this version
	list_t /* <sym_t> */ symbols;   /// All symbols specific for this version
	list_t /* <rel_t> */ relocs;    /// All symbol references specific for this version
	list_t /* <fun_t> */ funcs;     /// The code that make up this version
	list_t /* <blk_t> */ blocks;    /// The code that make up this version, in terms
	                                /// of basic blocks

	graph_t /* <fun_t> */ fcg;      /// The Function Call Graph of this version

	ver_t *next;
};


obj_t *executable_load(const char *path);


void executable_write(const char *path);


ver_t *version_create(void);


ver_t *version_switch(unsigned int number);


/************************************************************
*   Sections, symbols and references
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
	const char *name;               /// The name of this section (possibly not needed
	                                /// as it can be recovered from symbol->name)

	sec_type_t type;                /// DATA, CODE, RELOC, DEBUG, etc...
	unsigned long flags;            /// ALLOC, LOAD, READ, WRITE, etc...

	void *payload;                  /// Section contents
	size_t size;                    /// The size of this section (possibly not needed
	                                /// as it can be recovered from symbol->size)

	sym_t *symbol;                  /// The symbol representing this section
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
	const char *name;               /// The name of this symbol

	sym_type_t type;                /// FUNCTION, OBJECT, etc...
	unsigned long flags;            /// LOCAL, GLOBAL, WEAK, etc...

	void *payload;                  /// Symbol contents
	size_t size;                    /// The size of this symbol

	union {                         /// What the symbol represents...
		fun_t *function;              /// ...a function
		sec_t *section;               /// ...a section
		                              /// ...anything else?
	} is;

	union {                         /// Relocations associated to this symbol...
		list_t /* <rel_t> */ source;  /// ...when the symbol owns the relocation
		list_t /* <rel_t> */ dest;    /// ...when the relocation refers to the symbol
	} rel;

	sec_t *sec;                     /// The section that contains this symbol
	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which the symbol contents can be found
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
		ins_t *instr;                 /// ...(in this instruction)
	} in;

	struct {                        /// Relocation referring...
		sym_t *symbol;                /// ...to this symbol
		off_t addend;                 /// ...at this displacement
		ins_t *instr;                 /// ...(to this instruction)
	} to;
};


sec_t *section_create(const char *name, sec_type_t type, unsigned long flags);


sec_t *section_find(sec_t *match);


sec_t *section_find_byname(const char *name);


sym_t *symbol_create(const char *name, sym_type_t type, unsigned long flags);


sym_t *symbol_find(sym_t *match);


sym_t *symbol_find_byname(const char *name);


/************************************************************
*   Functions, blocks and instructions
************************************************************/

struct function {
	const char *name;               /// The name of this function (possibly not needed
	                                /// as it can be recovered from symbol->name)

	// fun_type_t type;                /// Anything useful here?

	graph_t /* <blk_t> */ cfg;      /// The CFG of this function
	list_t /* <blk_t> */ blocks;    /// The code that make up this function, in terms
	                                /// of basic blocks

	sym_t *symbol;                  /// The symbol representing this function
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

	list_t /* <ins_t> */ instr;     /// The code that make up this block, in terms
	                                /// of instructions

	// Presets-related fields
	void *smtracer;

	size_t size;                    /// The size of this block in bytes
	size_t length;                  /// The number of instructions that make up this block
};


typedef enum {
	INSERT_BEFORE,
	INSERT_AFTER,
} ins_insert_mode_t;


struct instruction {
	unsigned long flags;            /// MEMORY, ALGEBRIC, LOGIC, STACK, etc...

	addr_t offset;                  /// The offset from the beginning of the section
	                                /// at which this instruction can be found
	size_t size;                    /// The size of this instruction

	                                //  Other fields... see libasm!

	struct {                        /// Jumptable for this instruction
		size_t fanout;                /// Number of detected targets
		list_t /* <ins_t> */ instr;   /// List of target instructions
	} to;

	struct {                        /// Inverse jumptable for this instruction
		list_t /* <ins_t> */ instr;   /// List of instructions that jump to this instruction
	} from;

	union {                         /// Relocations associated to this instruction...
		list_t /* <rel_t> */ source;  /// ...when the instruction owns the relocation
		list_t /* <rel_t> */ dest;    /// ...when the relocation refers to the instruction
	} rel;
};


fun_t *function_create(const char *name);


fun_t *function_find(fun_t *match);


fun_t *function_find_byname(const char *name);


fun_t *function_find_byblock(blk_t *block);


fun_t *function_find_byinstr(ins_t *instr);


blk_t *block_find_byinstr(ins_t *instr);


ins_t *instr_insert(const char *mnemonic, ins_t *pivot, ins_insert_mode_t where);


void instr_remove(ins_t *instr);


#endif /* _IBR_H */
