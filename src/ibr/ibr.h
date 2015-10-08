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

struct _instruction {
	unsigned long   flags;
	unsigned long long  orig_addr;
	unsigned long long  new_addr;
	unsigned int    size;
	unsigned int    opcode_size;  // [DC] To keep trace of the opcode size
	union {
		insn_info_x86   x86;
	} i;

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

	struct _symbol *reference;
	struct _symbol *pointedby;
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
  void *vptracker;

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

typedef enum {
	SYMBOL_LOCAL,
	SYMBOL_GLOBAL,
	SYMBOL_WEAK
} symbol_bind;

struct _symbol {
	symbol_type     type;     /// The hijacker's local type specification of the symbol
	symbol_bind   bind;     /// The hijacker's local bind specification of the symbol
	unsigned char *name;      /// Pointer to the buffer holding the symbol's name
	unsigned int  size;   /// Size of the symbol, could be zero (e.g. for SYMBOL_UNDEF)
	unsigned int  secnum;     /// Index of the section the symbol belongs to
  section *sec;             // [SE] Section the symbol belongs to
	unsigned int  index;      /// Symbol's index within the symbol table
	unsigned long long  position;   /// Offset positioning within the symbol section
	void *initial; /// [SE] Symbol's initialization value
	function *func; /// [SE] The function related to the symbol (if any)
	struct _relocation {
//    struct _symbol *from;   /// Symbol from which the relocation applies
		insn_info *ref_insn;    /// Instruction where the relocation is applied
		long long offset;     /// The offset from the reference symbol's position
		long addend;        /// The offset from the target symbol
		unsigned char type;     /// The type of the relocation
		unsigned char *secname;   /// Name of the relocation section where to add the entry
	} relocation;
	int version;  /// Integer indicating to which instrumenting version it belongs
	bool    duplicate;    /// Flag that tells if symbol is a duplicate
	bool    referenced;   /// Flag indicating the symbol has been resolved
	long    extra_flags;  /// Maintains the info field of the ELF's symbol (either bind and type) # ridondante
	struct _symbol  *next;
};

struct _reloc {
	long long offset;
	unsigned char *name;
	symbol *symbol;
	unsigned int s_index;
	int type;
	int addend;
	struct _reloc *next;
};


/* Functions */

struct _function {
	block *begin_blk;        // [SE]
	block *end_blk;          // [SE]

  block *source;           // Starting block of the cfg
  linked_list calledfrom;  // List of basic blocks that call this function
  linked_list callto;      // List of functions that are called by this function

	int     passes;
	unsigned char   *name;
	unsigned long long  orig_addr;
	unsigned long long  new_addr;
	insn_info   *insn;
	symbol      *symbol;  // [DC] Added reference to the relative symbol
	struct _function *next;
};


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

struct _section {
	section_type    type;
	unsigned int  index;
	unsigned char *name;
	void    *header;
	void    *payload;
	void    *ptr;   // [DC] Payload's file pointer (emit stage)
	void    *reference; // [DC] May represent a reference to a relocation entry (emit stage)
	struct _section *next;
};


/* instruction.c */

extern insn_info *find_insn(function *func, unsigned long long addr, insn_address_type type);
extern insn_info *find_last_insn(function *functions);
extern int insert_instructions_at(insn_info *target, unsigned char *binary, size_t size,
	insn_insert_mode mode, insn_info **last);
extern int substitute_instruction_with(insn_info *target, unsigned char *binary, size_t size,
	insn_info **last);
extern insn_info *clone_instruction(insn_info *insn);
extern insn_info *clone_instruction_list(insn_info *insn);
extern void add_call_instruction(insn_info *target, unsigned char *func, insn_insert_mode mode, insn_info **instr);
extern void set_jumpto_reference(insn_info *jump, insn_info *target);
extern void set_jumptable_entry(insn_info *jump, insn_info *entry, unsigned int idx);
extern void set_virtual_reference(insn_info *target, insn_info *virtual);
extern void update_instruction_addresses(void);
extern void update_jump_displacements(void);

/* symbol.c */

extern symbol *find_symbol(unsigned char *name);
extern symbol *create_symbol_node(unsigned char *name, symbol_type type, symbol_bind bind, int size);
extern symbol *symbol_check_shared(symbol *sym);
extern symbol *clone_symbol(symbol *sym);

/* function.c */

extern function *find_func(insn_info *target);
extern function *find_func_from_sym(symbol *sym);
extern function *create_function_node(char *name, insn_info *code);
extern function *clone_function(function *func, char *suffix);
extern function *clone_function_list(function *func, char *suffix);
extern function *clone_function_descriptor(function *original, char *name);

/* section.c */

extern section *find_section(unsigned int idx);
// extern reloc *find_reloc(section *sec, unsigned long offset);
extern section *add_section(section_type type, int secndx, void *payload, section **first);

/* block.c */

extern block *block_create(void);
extern block *block_split(block *node, insn_info *breakpoint, block_split_mode mode);
extern block *block_find(insn_info *instr);
extern void block_link(block *from, block *to, block_edge_type type);
extern void block_tree_dump(char *filename, char *mode);
extern void block_graph_dump(function *func, char *filename, char *mode);
extern block *block_graph_create(function *functions);
extern void block_graph_visit(block_edge *edge, graph_visit *visit);


#endif /* _IBR_H */
