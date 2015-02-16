
/**
 * This file provides functions to manipulate parsed ELF structure.
 */

#include <stdio.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>

#include <executable.h>
#include <instruction.h>

#include "handle-elf.h"

symbol * find_symbol (char *name) {
	symbol *sym;
	
	sym = PROGRAM(symbols);
	while(sym) {
		if(!strcmp(sym->name, name))
			return sym;
		sym = sym->next;
	}
	
	return NULL;
}

void instruction_rela_node (symbol *sym, insn_info *insn, unsigned char type) {
	symbol *ref;		// a new relocation entry is a duplicate of the referenced symbol;
	long addend;
	
	hnotice(3, "Adding a RELA node to '%s'\n", sym->name);
	
	switch(type) {
		case RELOCATE_RELATIVE_32:
		case RELOCATE_RELATIVE_64:
			addend = (long)insn->opcode_size - (long)insn->size;	// consider that the addend is backward and -(a - b) == (b - a)
			break;
		
		case RELOCATE_ABSOLUTE_32:
		case RELOCATE_ABSOLUTE_64:
			addend = 0;
			break;
	}
	
	switch(type) {
		case RELOCATE_RELATIVE_32:
			type = R_X86_64_PC32;
			break;
		
		case RELOCATE_RELATIVE_64:
			type = R_X86_64_PC64;
			break;
		
		case RELOCATE_ABSOLUTE_32:
			type = R_X86_64_32;
			break;
		
		case RELOCATE_ABSOLUTE_64:
			type = R_X86_64_64;
			break;
		
		default:
			type = R_X86_64_PC32;
	}
	
	// Check if the symbol is already been referenced,
	// if this is the case, it returns a duplicate
	ref = symbol_check_shared(sym);
	ref->referenced = 1;
	ref->relocation.addend = addend;
	ref->relocation.type = type;
	ref->relocation.secname = ".text";
	
	insn->reference = ref;

	hnotice(3, "New RELA node has been created from symbol '%s' %+d to the instruction at address <%#08lx>\n",
		sym->name, ref->relocation.addend, insn->new_addr);
}


void create_rela_node (symbol *sym, long long offset, long addend, char *secname) {
	unsigned char type;

	// Decide the relocation's type accordingly to the relocation specifications
	if(!strcmp(secname, ".text")) {

		// Relocatation applies in the .text section towards symbol 'sym'
		switch(sym->type) {
			case SYMBOL_SECTION:
				type = R_X86_64_32;
				break;
			
			default:
				type = R_X86_64_PC32;
		}
	} else if(!strcmp(secname, ".rodata")) {
		// Relocation applies in the .rodata section towards another section symbol
		type = R_X86_64_64;
	} else {
		// Default value
		type = R_X86_64_64;
	}

	sym = symbol_check_shared(sym);
	sym->referenced = 1;
	sym->relocation.addend = addend;
	sym->relocation.offset = offset;
	sym->relocation.type = type;
	sym->relocation.secname = secname;


	hnotice(3, "New RELA node of type %d has been created to symbol '%s' %+d in section '%s'\n",
		sym->relocation.type, sym->relocation.offset, sym->name, sym->relocation.addend, secname);
}


/**
 * Adds raw data to the section pointed to by the symbol 'sym'
 *
 * @param sym Pointer to the symbol descriptor of the target section
 * @param data Generic pointer to data to add
 * @param size The size in bytes of the buffer 'data'
 */
void add_data_to_section (symbol *sym, void *data, size_t size) {

	// Checks if the symbol passed is really of type 'SECTION'
	if(sym->type != SYMBOL_SECTION) {
		hinternal();
	}
	
	hprint("Actually adding data to sections is not yet enabled\n");
	
	/*data = PROGRAM(rawdata);
	if(!data) {
		data = (void *) malloc(sizeof(size));
	}*/

	// TODO: dovrebbe copiare i dati all'interno di un descrittore di sezione,
	// in questo modo, in fase di emit, automaticamente verrà ampliata
	// la sezione data con i nuovi dati aggiunti.
}

symbol * create_symbol_node (char *name, int type, int bind, int size) {
	symbol *sym;
	symbol *node;

	// Check whether the symbol requested is already present
	node = PROGRAM(symbols);
	while(node) {
		if(!strcmp(node->name, name))
			return node;
		sym = node;
		node = node->next;
	}

	// create a symbol node
	node = (symbol *) malloc(sizeof(symbol));
	if(!node)  {
		herror(true, "Out of memory!\n");
	}
	bzero(node, sizeof(symbol));

	//node->name = (char *) malloc(strlen(name));
	//strcpy(node->name, name);
	node->name = name;
	node->type = type;
	node->bind = bind;
	node->size = size;

	// add to the symbol list (sym holds the last symbol yet)
	/*sym = PROGRAM(symbols);
	while (sym->next) {
		sym = sym->next;
	}*/
	sym->next = node;

	hnotice(3, "New %s symbol '%s' node of type %d has been created\n",
		sym->bind == SYMBOL_LOCAL ? "local" : sym->bind == SYMBOL_GLOBAL ?  "global" : "weak", node->name, node->type);

	return node;
}


symbol * symbol_check_shared (symbol *sym) {
	symbol *prev, *curr;

	// Check if the field offset is not empty, in this case the symbol
	// is shared and we must create and link a new copy of to store
	// the new relocation offset.
	if(sym->referenced) {

		hnotice(5, "Multiple reference to '%s', duplicating symbol...\n", sym->name);

		// seek the end of the collision list starting from
		// passed symbol
		prev = curr = sym;
		while(curr->next && curr->next->index == sym->index) {
			prev = curr;
			curr = curr->next;
		}

		// copy the last symbol copy
		symbol *s = (symbol *) malloc(sizeof(symbol));
		memcpy(s, sym, sizeof(symbol));

		// this symbol is marked as a copy
		s->duplicate = 1;

		// update the list
		s->next = prev->next;
		prev->next = s;

		// return the new created duplicate
		return s;
	}

	hnotice(5, "First reference to '%s'\n", sym->name);
	// no duplicates, return the symbol itself
	return sym;
}


/**
 * Clone the whole symbol list of the internal representation. This is done
 * in order to support future multiversioning of executable and object files.
 *
 * @return The pointer to the first symbol descriptor of the clone list
 */
static symbol * clone_symbol_list () {
	symbol *sym, *clone, *head;

	sym = PROGRAM(symbols);
	head = clone = (symbol *) malloc(sizeof(symbol));

	while(sym) {
		memcpy(clone, sym, sizeof(symbol));
		clone->next = (symbol *) malloc(sizeof(symbol));
		clone = clone->next;
		
		sym = sym->next;
	}
	
	return head;
}

/**
 * Clone the whole function list of the internal representation. This is done
 * in order to support future multiversioning of executable and object files.
 * Cloning the function means to clone their instructions as well.
 *
 * @return The pointer to the first function descriptor of the clone list
 */
static function * clone_function_list () {
	function *func, *clone, *head;
	insn_info *insn, *insn_clone;
	symbol *sym;

	func = PROGRAM(code);
	head = clone = (function *) malloc(sizeof(function));

	while(func) {
		memcpy(clone, func, sizeof(function));
		insn_clone = (insn_info *) malloc(sizeof(insn_info));
		
		insn = func->insn;
		clone->insn = insn_clone;
		
		while(insn) {
			memcpy(insn_clone, insn, sizeof(insn_info));
			insn_clone->next = (insn_info *) malloc(sizeof(insn_info));
			insn_clone = insn_clone->next;
			
			insn = insn->next;
		}

		clone->next = (function *) malloc(sizeof(function));
		clone = clone->next;
		
		func = func->next;
	}
	
	return head;
}


int switch_executable_version (int version) {
	symbol *symbols;
	function *code;
	
	// Checks whether the version is already present in the list
	// otherwise it creates a new one by cloning symbols and code
	if(!version || version > PROGRAM(version)) {

		// Increment the current version and clone symbols and functions
		version = PROGRAM(version)++;
		code = clone_function_list();
		symbols = clone_symbol_list();

		hnotice(3, "Version %d of the executable's binary representation created\n", version);
	}
	// Update pointers to the actual symbol and code lists
	PROGRAM(v_code)[version] = code;
	PROGRAM(v_symbols)[version] = symbols;

	PROGRAM(code) = code;
	PROGRAM(symbols) = symbols;
	
	hnotice(2, "Switched to version %d\n", version);

	return version;
}
