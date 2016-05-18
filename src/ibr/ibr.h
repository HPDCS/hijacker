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
* @brief Structures to map object files to Hijacker's intermediate binary representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @author Simone Economo
*/

#pragma once
#ifndef _IBR_H
#define _IBR_H

#include <stddef.h>

#include <utils.h>
#include <instruction.h>
#include <elf/elf-defs.h>

typedef struct _instruction insn_info;
typedef struct _block block;
typedef struct _function function;
typedef struct _symbol symbol;
typedef struct _reloc reloc;
typedef struct _section section;

/* Instructions */

typedef enum {
	ORIG_ADDR,
	NEW_ADDR
} insn_address_type;

typedef enum {
	INSERT_BEFORE,
	INSERT_AFTER,
	SUBSTITUTE
} insn_insert_mode;


#define instr_reference_weak(instr) \
  ((instr)->reference.first ? (instr)->reference.first->elem : NULL)


struct _instruction {
	unsigned int index;
	unsigned long   flags;
	unsigned long long  orig_addr;
	unsigned long long  new_addr;
	unsigned int    size;
	unsigned int    opcode_size;  // [DC] To keep trace of the opcode size
	union {
		insn_info_x86   x86;
	} i;

	char *secname;     // [SE] Code section the instruction belongs to

	struct _instruction *jumpto;

	// [SE] Jump table (used for both indirect jumps and calls)
	struct {
		unsigned long long size;
		struct _instruction **entry;
	} jumptable;

	// [SE] Which instructions can reach the current one?
	linked_list targetof;

	// [SE] The instruction that 'virtually' represents the current one
	// as the target of a jump instruction.
	struct _instruction *virtual;

	linked_list reference;
	linked_list pointedby;

	// struct _symbol *reference;
	// struct _symbol *pointedby;
	bool written;		// Tell if the current instruction has been currently emitted

	// Parent instruction in the previous IBR version
	struct _instruction *parent;

	struct _instruction *prev;  // Instructions are organized in a chain
	struct _instruction *next;
};


/* Blocks */

typedef enum {
	SPLIT_FIRST,
	SPLIT_LAST
} block_split_mode;

typedef enum {
	BLOCK_GENERIC,
	BLOCK_LOOP_HEADER,
	BLOCK_LOOP_FOOTER,
	BLOCK_BRANCH_HEADER,
	BLOCK_BRANCH_THEN,
	BLOCK_BRANCH_ELSE
} block_type;

typedef enum {
	EDGE_GOTO,
	EDGE_THEN,
	EDGE_ELSE,
	EDGE_FORCED,
	EDGE_IND,
	EDGE_CALLRET,
	EDGE_INIT
} block_edge_type;

typedef enum {
	EDGE_NEXT,
	EDGE_BACK
} block_edge_dir;

typedef struct {
	block_edge_type type;
	block_edge_dir dir;
	block *from;
	block *to;
} block_edge;

typedef struct {
	linked_list sources;
} block_graph;

struct _block {
	unsigned int id;          // Unique identifier for the block
	unsigned long length;     // Number of instructions that make up the block
	insn_info *begin;         // First instruction of the block
	insn_info *end;           // Last instruction of the block
	struct _block *next;      // Ordered list of blocks

	// Presets-related fields
	void *smtracer;

	// Callgraph-related fields
	function *callto;         // The function being called by this block
	struct {
		unsigned long long size;
		function **entry;
	} calltable;              // A list of potential functions that can be called by this block

	// Flowgraph-related fields
	block_type type;          // The type of a block wrt control flow structures
	linked_list out;          // Double-linked list of next blocks
	linked_list in;           // Double-linked list of previous blocks
	bool visited;             // True if the block was already met in the current visit
	bool active;              // True if the block is in the current path (only for DFS!)

	// Tree-related fields
	int balance;              // The balance factor of the AVL tree rooted at this block
	unsigned int height;      // The height of the AVL tree rooted at this block
	struct _block *left;      // Left child in the AVL tree
	struct _block *right;     // Right child in the AVL tree
	struct _block *parent;    // Parent block in the AVL tree
};


/* Symbols */

typedef enum {
	SYMBOL_NULL,
	SYMBOL_VARIABLE,
	SYMBOL_FUNCTION,
	SYMBOL_UNDEF,
	SYMBOL_SECTION,
	SYMBOL_FILE,
	SYMBOL_TLS
} symbol_type;

extern const char *symbol_type_str[];

typedef enum {
	SYMBOL_LOCAL,
	SYMBOL_GLOBAL,
	SYMBOL_WEAK
} symbol_bind;

extern const char *symbol_bind_str[];

// FIXME: Incomplete list of relocations...
typedef enum {
	RELOC_PCREL_32,
	RELOC_PCREL_64,
	RELOC_TLSREL_32,
	RELOC_ABS_32,
	RELOC_ABS_32S,
	RELOC_ABS_64,
} reloc_type;

extern const char *reloc_type_str[];

struct _symbol {
	symbol_type type;     /// The hijacker's local type specification of the symbol
	symbol_bind bind;     /// The hijacker's local bind specification of the symbol

	unsigned int index;   /// Symbol's index within the symbol table
	char *name;  /// Pointer to the buffer holding the symbol's name
	unsigned int size;    /// Size of the symbol, could be zero (e.g. for SYMBOL_UNDEF)

	unsigned int secnum;  /// Index of the section the symbol belongs to
	section *sec;         /// Section the symbol belongs to (for section symbols it's the section itself)
	unsigned long long offset;   /// Displacement from the beginning of the section

	void *payload;        /// Symbol's initial value
	function *func;       /// The function associated with the symbol (if a symbol section)

	struct _relocation {
		unsigned char type;            /// The type of the relocation

		section *sec;                  /// Source relocation section
		unsigned long long offset;     /// Displacement from the beginning of the section

		long addend;                   /// Displacement from the beginning of the symbol

		insn_info *target_insn;        /// Instruction where the relocation is applied (if any)
	} relocation;

	int version;       /// Integer indicating to which instrumenting version it belongs
	bool duplicate;    /// Flag that tells if symbol is a duplicate
	bool referenced;   /// Flag indicating the symbol has been referenced
	bool authentic;

	struct _symbol  *next;
};

struct _reloc {
	int type;

	unsigned int symnum;  // index of symbol relocation refers to
	symbol *sym;
	int addend;    // explicit displacement to add to the offset

	unsigned int secnum; // index of section relocation targets
	section *sec;
	long long offset;    // offset within the section to which apply the relocation

	// unsigned char *name;
	struct _reloc *next;
};


/* Functions */

struct _function {
	char   *name;

	block *begin_blk;        // [SE]
	block *end_blk;          // [SE]

	// Callgraph-related fields
	block *source;           // Starting block of the cfg
	linked_list calledfrom;  // List of basic blocks that call this function
	linked_list callto;      // List of functions that are called by this function
	bool visited;            // True if the function was already met in the current visit

	bool overload;
	linked_list alias;		// A list of possible aliases of this function

	insn_info   *begin_insn;
	insn_info   *end_insn;
	symbol      *symbol;  // [DC] Added reference to the relative symbol

	struct _function *next;
};

#define functions_overlap(a, b)\
	(a && b && a->symbol->sec == b->symbol->sec\
		&& a->begin_insn->new_addr == b->begin_insn->new_addr)


/* Sections and relocation entries */

typedef enum {
	SECTION_NULL,
	SECTION_CODE,
	SECTION_SYMBOLS,
	SECTION_NAMES,
	SECTION_RELOC,
	SECTION_TLS,
	SECTION_RAW
} section_type;

extern const char *section_type_str[];

struct _section {
	section_type type;
	unsigned int index;
	char *name;
	unsigned long long offset;

	void *payload;  // In-memory section contents
	void *header;

	symbol *sym;

	// Emit stage
	void *ptr;   // [DC] Payload's file pointer
	void *reference; // [DC] May represent a reference to a relocation entry

	struct _section *next;
};


/* instruction.c */

insn_info *find_insn(function *func, unsigned long long addr, insn_address_type type);
insn_info *find_insn_cool(insn_info *head, unsigned long long addr);
insn_info *find_last_insn(function *functions);
void parse_instruction_bytes(unsigned char *bytes, unsigned long int *pos, insn_info **final);
int insert_instructions_at(insn_info *target, unsigned char *binary, size_t size,
	insn_insert_mode mode, insn_info **last);
int substitute_instruction_with(insn_info *target, unsigned char *binary, size_t size);
insn_info *clone_instruction(insn_info *insn);
insn_info *clone_instruction_list(insn_info *insn);
void add_call_instruction(insn_info *target, char *func, insn_insert_mode mode, insn_info **instr);
void add_jump_instruction(insn_info *target, char *name, insn_insert_mode mode, insn_info **instr);
void set_jumpto_reference(insn_info *jump, insn_info *target);
void set_jumptable_entry(insn_info *jump, insn_info *entry, unsigned int idx);
void set_virtual_reference(insn_info *target, insn_info *virtual);
void link_jump_instructions(void);
void update_instruction_addresses(int version);
void update_jump_displacements(int version);
void set_call_displacement(insn_info *jump, insn_info *target);

/* symbol.c */

symbol *find_symbol(size_t index);
symbol *find_symbol_by_name(char *name);
symbol *create_symbol_node(char *name, symbol_type type, symbol_bind bind, int size);
symbol *symbol_create(char *name, symbol_type type, symbol_bind bind,
	section *sec, size_t size);
symbol *symbol_create_from_ELF(Elf_Sym *elfsym);
void symbol_append(symbol *sym, symbol **head);
symbol *symbol_check_shared(symbol *sym);
symbol *symbol_clone(symbol *sym, char *suffix);
void find_relocations(symbol *symbols, section *in, symbol *to, linked_list *list);
symbol *symbol_rela_create(symbol *sym, reloc_type type,
	unsigned long long offset, long addend, section *sec);
symbol *symbol_rela_create_from_ELF(reloc *rel);
symbol *symbol_instr_rela_create(symbol *sym, insn_info *insn, reloc_type type);
symbol *symbol_rela_clone(symbol *sym);

/* function.c */

function *find_func_cool(section *sec, unsigned long long addr);
function *find_func_from_instr(insn_info *instr, insn_address_type type);
function *find_func_from_addr(unsigned long long addr);
function *function_create_from_insn(char *name, insn_info *code, section *sec);
function *function_create_from_bytes(char *name, unsigned char *code, size_t size, section *sec);
function *clone_function(function *func, char *suffix);
function *clone_function_list(function *func, char *suffix);
// function *clone_function_descriptor(function *original, char *name);

/* section.c */

section *find_section(unsigned int idx);
section *find_section_by_name(char *name, int version);
// reloc *find_reloc(section *sec, unsigned long offset);
section *section_create(char *name, section_type type, void *payload);
section *section_create_from_ELF(size_t index, section_type type);
void section_append(section *sec, section **head);
section *section_clone(section *sec, char *suffix);

/* block.c */

block *block_create(void);
block *block_split(block *node, insn_info *breakpoint, block_split_mode mode);
block *block_find(insn_info *instr);
void block_link(block *from, block *to, block_edge_type type);
void block_tree_dump(char *filename, char *mode);
void block_graph_dump(function *func, char *filename, char *mode);
block *block_graph_create(void);
void block_graph_visit(block_edge *edge, graph_visit *visit);


#endif /* _IBR_H */
