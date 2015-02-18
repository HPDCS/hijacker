
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

int function_size (function *func) {
	insn_info *insn;
	int size;

	if(!func)
		return -1;

	insn = func->insn;
	size = 0;
	while(insn) {
		size += insn->size;
		insn = insn->next;
	}

	return size;
}

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
	node->version = PROGRAM(version);

	// add to the symbol list (sym holds the last symbol yet)
	/*sym = PROGRAM(symbols);
	while (sym->next) {
		sym = sym->next;
	}*/
	sym->next = node;

	hnotice(3, "New %s symbol '%s' node of type %d and size %d bytes has been created\n",
		sym->bind == SYMBOL_LOCAL ? "local" : sym->bind == SYMBOL_GLOBAL ?  "global" : "weak", node->name, node->type,
		node->size);

	return node;
}


function * create_function_node (char *name, insn_info *code) {
	function *func, *list;
	symbol *sym;
	insn_info *insn;
	int size;

	size = 0;
	insn = code;
	while(insn) {
		size += insn->size;
		insn = insn->next;
	}

	sym = create_symbol_node(name, SYMBOL_FUNCTION, SYMBOL_GLOBAL, size);

	func = (function *) malloc(sizeof(function));
	if(!func) {
		herror(true, "Out of memory!\n");
	}
	bzero(func, sizeof(function));

	func->name = name;
	func->symbol = sym;
	func->insn = code;

	list = PROGRAM(code);
	while(list->next) {
		list = list->next;
	}

	func->orig_addr = func->new_addr = (list->new_addr + list->symbol->size);
	func->symbol->position = func->orig_addr;
	list->next = func;

	hnotice(4, "New function '%s' created\n", name);

	return func;
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


static insn_info * clone_instruction (insn_info *insn) {
	insn_info *clone;

	clone = (insn_info *) malloc(sizeof(insn_info));
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	memcpy(clone, insn, sizeof(insn_info));

	clone->jumpto = NULL;
}


/**
 * Clone the whole instruction list of the function 'func'
 *
 */
static insn_info * clone_instruction_list (insn_info *insn) {
	insn_info *clone, *head;

	if(!insn)
		return NULL;

	head = clone = clone_instruction(insn);
	clone->prev = NULL;
	insn = insn->next;

	while(insn) {
		clone->next = clone_instruction(insn);
		clone->next->prev = clone;
		clone = clone->next;
		insn = insn->next;
	}

	return head;
}


static symbol * clone_symbol (symbol *sym) {
	symbol *clone;

	clone = (symbol *) malloc(sizeof(symbol));
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	memcpy(clone, sym, sizeof(symbol));

	return clone;
}


/**
 * Clone the whole symbol list of the internal representation. This is done
 * in order to support future multiversioning of executable and object files.
 *
 * @return The pointer to the first symbol descriptor of the clone list
 */
static symbol * clone_symbol_list (symbol *sym) {
	symbol *clone, *head;

	if(!sym)
		return NULL;

	head = clone = clone_symbol(sym);
	sym = sym->next;

	while(sym) {
		clone->next = clone_symbol(sym);
		clone = clone->next;
		sym = sym->next;
	}

	//================ DEBUG ================//
	hprint("Simboli copiati!\n");
	sym = head;
	while(sym) {
		printf("Simbolo '%s' di tipo %d (%p)\n", sym->name, sym->type, sym);
		sym = sym->next;
	}
	//=======================================//
	
	return head;
}


static function * clone_function (function *func, char *suffix) {
	function *clone;
	char *name;
	int size;

	if(!func)
		return NULL;

	// Allocates memory for the new descriptor
	clone = (function *) malloc(sizeof(function));
	if(!clone) {
		herror(true, "Out of memory!\n");
	}

	// Copies the original descriptor to the new one
	printf("Copio funzione '%s'\n", func->name);
	memcpy(clone, func, sizeof(function));

	// Updates the pointer to instruction list
	clone->insn = clone_instruction_list(func->insn);

	// Updates the symbol pointer (assume that symbols have been already be cloned)
	size = strlen(func->name) + strlen(suffix);
	name = (char *) malloc(sizeof(char) * size);
	bzero(name, size);
	strcpy(name, func->name);
	strcat(name, "_");
	strcat(name, suffix);

	size = function_size(clone);
	if(size < 0) {
		hinternal();
	}

	clone->symbol = create_symbol_node(name, SYMBOL_FUNCTION, SYMBOL_GLOBAL, size);
	clone->name = name;

	return clone;
}


/**
 * Clone the whole function list of the internal representation. This is done
 * in order to support future multiversioning of executable and object files.
 * Cloning the function means to clone their instructions as well.
 *
 * @return The pointer to the first function descriptor of the clone list
 */
static function * clone_function_list (function *func, char *suffix) {
	function *clone, *head;
	insn_info *insn, *insn_clone;

	if(!func)
		return NULL;

	head = clone = clone_function(func, suffix);
	func = func->next;

	while(func) {
		clone->next = clone_function(func, suffix);
		clone = clone->next;
		func = func->next;
	}


	//================ DEBUG ================//
	hprint("Istruzioni copiate!\n");
	func = head;
	while(func) {
		printf("Funzione '%s' (%p):\n", func->name, func);

		insn = head->insn;
		while(insn) {
			printf("\t%s <%#08lx> (%p)\n", insn->i.x86.mnemonic, insn->new_addr, insn);
			insn = insn->next;
		}
		printf("\n");
		
		func = func->next;
	}
	//=======================================//

	return head;
}


function * clone_function_descriptor (function *original, char *name) {
	function *clone;
	insn_info *insn;

	insn = clone_instruction_list(original->insn);
	clone = create_function_node(name, insn);

	hnotice(3, "Clone function '%s' into '%s' (version %d)\n", original->name, name, PROGRAM(version));

	return clone;
} 


int switch_executable_version (int version) {
	function *func, *code;

	PROGRAM(version) = version;
	
	// Checks whether the version is already present in the list
	// otherwise it creates a new one by cloning symbols and code
	if(!PROGRAM(v_code)[version]) {

		hnotice(2, "Version not present, cloning metadata for a new one\n");

		// Clones the whole code
		//SYMBOLS = clone_symbol_list(PROGRAM(symbols));
		code = func = clone_function_list(PROGRAM(v_code)[0], config.rules[version]->suffix);
		PROGRAM(v_code)[version] = code;
		PROGRAM(versions)++;

		// Relink jump instruction
		// By cloning each instruction will be unreferenced otherwise
		// we they still points to the old orginal copy which is uncorrect
		while(func) {
			link_jump_instruction(func);
			func = func->next;
		}

		hnotice(2, "Version %d of the executable's binary representation created\n", version);
	}

	PROGRAM(code) = PROGRAM(v_code)[version];
	
	hnotice(2, "Switched to version %d\n", version);

	return PROGRAM(version);
}
