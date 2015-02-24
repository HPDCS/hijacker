#pragma once
#ifndef _EXECUTABLE_H
#define _EXECUTABLE_H

#include <elf/elf-defs.h>
#include <coff/coff-defs.h>
#include <pe/pe-defs.h>

#include <instruction.h>
#include <rules.h>


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
	int			bind;			/// The hijacker's local bind specification of the symbol
	char		*name;			/// Pointer to the buffer holding the symbol's name
	unsigned int	size;		/// Size of the symbol, could be zero (e.g. for SYMBOL_UNDEF)
	int 		secnum;			/// Index of the section the symbol belongs to
	int 		index;			/// Symbol's index within the symbol table
	long long	position;		/// Offset positioning within the symbol section
	long long	initial;		/// Initialization symbol's value
	struct {
//		struct _symbol *from;		/// Symbol from which the relocation applies
		insn_info *ref_insn;		/// Instruction where the relocation is applied
		long long offset;			/// The offset from the reference symbol's position
		long addend;				/// The offset from the target symbol
		unsigned char type;			/// The type of the relocation
		unsigned char *secname;		/// Name of the relocation section where to add the entry
	} relocation;
	unsigned int	version;	/// Integer indicasting to which instrumenting verions it belongs
	bool		duplicate;		/// Flag that tells if symbol is a duplicate
	bool		referenced;		/// Flag indicating the symbol has been resolved
	long		extra_flags;	/// Maintains the info field of the ELF's symbol (either bind and type) # ridondante
	struct _symbol	*next;
} symbol;


typedef struct _function {
	int			passes;
	char			*name;
	unsigned long long	orig_addr;
	unsigned long long	new_addr;
	insn_info		*insn;
	symbol 			*symbol;	// [DC] Added reference to the relative symbol
	struct _function *next;
} function;


typedef struct _reloc {
	long long offset;
	char *name;
	symbol *symbol;
	int s_index;
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
	int		index;
	char	*name;
	void		*header;
	void		*payload;
	void		*ptr;		// [DC] Payoad's file pointer (emit stage)
	void 		*reference;	// [DC] May represent a reference to a relocation entry (emit stage)
	struct _section	*next;
} section;




#define EXECUTABLE_ELF	1
#define EXECUTABLE_PE	2
#define EXECUTABLE_COFF	3

#define MAX_VERSIONS	256

typedef struct _executable {
	int type;
	int insn_set;
	union {
		elf_file	elf;
		coff_file	coff;
		pe_file		pe;
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
} executable_info;



//extern void add_section(int type, void *header, void *payload);
extern void add_section(int type, int secndx, void *payload);
extern section *get_section_type(int type);
extern void load_program(char *path);


#endif /* _EXECUTABLE_H */

