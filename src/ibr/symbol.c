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
* @file symbol.c
* @brief Module to handle symbols in the Intermediate Representation
* @author Davide Cingolani
* @date July 13, 2015
*/

#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <ibr.h>

#include <elf/parse-elf.h>


const char *symbol_type_str[] = {
	"NULL", "VARIABLE", "FUNCTION", "UNDEF", "SECTION", "FILE", "TLS"
};

const char *symbol_bind_str[] = {
	"LOCAL", "GLOBAL", "WEAK"
};

const char *reloc_type_str[] = {
	"PCREL_32", "PCREL_64", "TLSREL_32", "ABS_32", "ABS_32S", "ABS_64",
};


size_t symbol_id(size_t nextid, bool update) {
	static size_t id = 0;

	if (nextid > id && update == true) {
		id = nextid;
	}

	return (update == true ? id : id++);
}


symbol *find_symbol(size_t index) {
	symbol *sym;

	for (sym = PROGRAM(symbols); sym; sym = sym->next) {
		if (sym->index == index && sym->authentic) {
			return sym;
		}
	}

	return NULL;
}


/**
 * Seeks the symbol descriptor associated with a given symbol name.
 *
 * @param name Buffer pointing to the name of the symbol.
 *
 * @return Pointer to the symbol descriptor found, if any, or <em>NULL</em>.
 */
symbol *find_symbol_by_name(unsigned char *name) {
	symbol *sym;

	// TODO: Multiple symbols with the same name can exist!
	for (sym = PROGRAM(symbols); sym; sym = sym->next) {
		if (str_equal(sym->name, name) && sym->authentic)
			return sym;
	}

	return NULL;
}


/**
 * Given the name of a symbol, the function checks whether it exists in the
 * symbol list and, in the positive case, it returns this symbol.
 * Otherwise the function will create a new symbol with the specified attributes.
 * Note that the attributes passed are only used if a new symbol has to be created
 * from scratch.
 *
 * @param name Pointer to the string that represents the symbol's name.
 * @param type Integer representing the constant for the internal symbol's type.
 * @param bind Integer representing the constant for the internal symbol's binding.
 * @param size Size in bytes of the symbol, if present.
 *
 * @return Pointer to a symbol descriptor matching the name requested.
 */
symbol *create_symbol_node(unsigned char *name, symbol_type type, symbol_bind bind, int size) {
	symbol *sym;
	symbol *node;
	// unsigned int index;

	// Check whether the symbol requested is already present
	node = PROGRAM(symbols);
	while(node) {
		if(!strcmp((const char *)node->name, (const char *)name)){
			hnotice(3, "%s symbol '%s' (%d) node found [ver = %d]\n",
				node->bind == SYMBOL_LOCAL ? "Local" : node->bind == SYMBOL_GLOBAL ?  "Global" : "Weak",
				node->name, node->index, node->version);
			return node;
		}
		sym = node;
		node = node->next;
	}

	// create a symbol node
	node = (symbol *) malloc(sizeof(symbol));
	if(!node)  {
		herror(true, "Out of memory!\n");
	}
	bzero(node, sizeof(symbol));

	node->name = (char *) malloc(strlen((const char *) name) + 1);
	strcpy(node->name, name);
	//node->name = name;
	node->type = type;
	node->bind = bind;
	node->size = size;
	node->version = PROGRAM(version);


	if (bind == SYMBOL_LOCAL) {
		// in case the symbol is local append after the last local symbol
		// in the list
		sym = PROGRAM(symbols);
		while(sym) {
			if(sym->next->bind != SYMBOL_LOCAL)
				break;
			sym = sym->next;
		}
		// index = sym->index + 1;

		node->next = sym->next;
		sym->next = node;

		// update the indexes of all the other symbols
		/*sym = node;
		while(sym) {
			if(sym->duplicate) {
				sym->index = idx - 1;
				sym = sym->next;
				continue;
			}

			sym->index = index++;
			printf("%s - %d (t=%d, b=%d)\n", sym->name, sym->index, sym->type, sym->bind);
			sym = sym->next;
		}*/
	}

	else if (bind == SYMBOL_GLOBAL) {
		// in case the symbol is global adds it to the tail
		// add to the symbol list (here, sym holds the last symbol yet)
		sym->next = node;
		node->index = sym->index + 1;
	}

	hnotice(3, "New %s symbol '%s' (%d) in '%s' node of type %d and size %d bytes has been created\n",
		node->bind == SYMBOL_LOCAL ? "local" : node->bind == SYMBOL_GLOBAL ?  "global" : "weak", node->name, node->index, node->sec,
		node->type, node->size);

	return node;
}


symbol *symbol_create(char *name, symbol_type type, symbol_bind bind,
	section *sec, size_t size) {
	symbol *sym;

	sym = (symbol *) calloc(sizeof(symbol), 1);

	sym->name = (char *) malloc(strlen((const char *) name) + 1);
	strcpy(sym->name, name);

	sym->type = type;
	sym->bind = bind;

	if (sec) {
		sym->secnum = sec->index;
		sym->sec = sec;
	}

	sym->size = size;

	sym->index = symbol_id(0, false);
	sym->version = PROGRAM(version);
	sym->authentic = true;

	// We now append the symbol to the global list of symbols
	symbol_append(sym, &PROGRAM(symbols));

	hnotice(3, "New %s/%s symbol '%s' (%d) in '%s' (%d) of size %d bytes has been created from scratch\n",
		symbol_type_str[sym->type], symbol_bind_str[sym->bind],
			sym->name, sym->index, (sym->sec ? sym->sec->name : "(none)"), sym->secnum, sym->size);

	return sym;
}

symbol *symbol_create_from_ELF(Elf_Sym *elfsym) {
	symbol *sym;
	unsigned int symtype, symbind;

	sym = (symbol *) calloc(sizeof(symbol), 1);

	sym->name = strtab(symbol_info(elfsym, st_name));

	symtype = ( ELF(is64) ? ELF64_ST_TYPE(symbol_info(elfsym, st_info)) : ELF32_ST_TYPE(symbol_info(elfsym, st_info)) );
	symbind = ( ELF(is64) ? ELF64_ST_BIND(symbol_info(elfsym, st_info)) : ELF32_ST_BIND(symbol_info(elfsym, st_info)) );

	switch(symtype) {
		case STT_FUNC:
			sym->type = SYMBOL_FUNCTION;
			break;

		case STT_COMMON:
		case STT_OBJECT:
			sym->type = SYMBOL_VARIABLE;
			break;

		case STT_NOTYPE:
			sym->type = SYMBOL_UNDEF;
			break;

		case STT_SECTION:
			sym->type = SYMBOL_SECTION;
			break;

		case STT_FILE:
			sym->type = SYMBOL_FILE;
			break;

		case STT_TLS:
			sym->type = SYMBOL_TLS;
			break;

		default:
			hinternal();
	}

	switch(symbind) {
		case STB_LOCAL:
			sym->bind = SYMBOL_LOCAL;
			break;

		case STB_GLOBAL:
			sym->bind = SYMBOL_GLOBAL;
			break;

		case STB_WEAK:
			sym->bind = SYMBOL_WEAK;
			break;

		default:
			hinternal();
	}

	sym->secnum = symbol_info(elfsym, st_shndx);

	// TODO: Decidere cosa fare quando non si trova la sezione
	if (sym->secnum != SHN_ABS && sym->secnum != SHN_COMMON && sym->secnum != SHN_UNDEF) {
		sym->sec = find_section(sym->secnum);
	}

	sym->size = symbol_info(elfsym, st_size);
	sym->index = symbol_id(0, false);
	sym->offset = symbol_info(elfsym, st_value);

	// NOTE: "initial" was intended here as the initial value, but st_value
	// refers to the offset within the section.
	// This was breaking the generation of references in case of local calls.
	// I don't know if it is safe to remove the "initial" field anyhow

	// sym->initial = symbol_info(elfsym, st_value);
	// sym->extra_flags = symbol_info(elfsym, st_info);

	sym->version = PROGRAM(version);
	sym->authentic = true;

	// We now append the symbol to the global list of symbols
	symbol_append(sym, &PROGRAM(symbols));

	hnotice(3, "New %s/%s symbol '%s' (%d) in '%s' of size %d bytes has been created from ELF\n",
		symbol_type_str[sym->type], symbol_bind_str[sym->bind],
			sym->name, sym->index, (sym->sec ? sym->sec->name : "(none)"), sym->size);

	return sym;
}

void symbol_append(symbol *sym, symbol **head) {
	symbol *curr, *prev;
	symbol *duplicate;

	// We append the symbol to an input list of symbols, at a position
	// which depends on the symbol binding:
	// - If local, append to the last local symbol in the list;
	// - If global, append to the end of the list.

	// printf("SYMBOL TO ADD: %s %s %p\n", sym->name, symbol_bind_str[sym->bind], sym);

	if (head == NULL) {
		hinternal();
	}

	if (*head == NULL) {
		*head = sym;
	} else {
		curr = *head;
		prev = NULL;

		// duplicate = find_symbol_by_name(sym->name);
		for (duplicate = *head; duplicate != NULL; duplicate = duplicate->next) {
			if (duplicate->name[0] == '\0')
				continue;

			if (str_equal(duplicate->name, sym->name)) {
				// NOTE: In the future it would be posible to collapse two function symbols
				// in the case they have the same byte footprint
				char *new_name = malloc(256 * sizeof(char));
				
				sprintf(new_name, "%s_%d", sym->name, duplicate->index);
				duplicate->name = new_name;

				herror(false, "Two symbol with same names are found ('%s'); change into '%s'\n",
					sym->name, new_name);
			}
		}


		while (curr) {
			if (sym->bind == SYMBOL_LOCAL && curr->bind != SYMBOL_LOCAL) {
				break;
			}

			prev = curr;
			curr = curr->next;
		}

		if (prev == NULL) {
			*head = sym;
			sym->next = curr;
		} else {
			sym->next = prev->next;
			prev->next = sym;
		}
	}

}

/**
 * Verifies if the passed symbol is shared.
 * In case the symbol is shared among multiple relocation entries, then a copy of it
 * will be created in order to save the new offset. During the emit phase, each
 * additional copy of the symbol will be skipped but the relative offset added to
 * a new relocation entry whose the symbol refers to.
 *
 * Note: The function will update the list of symbols by adding possible duplicates.
 *
 * @param sym Pointer to the symbol descriptor to check.
 *
 * @return Pointer to the symbol descriptor of the new symbol, or to the symbol
 * passed as parameter in case no sharing happened.
 */
symbol *symbol_check_shared(symbol *sym) {
	symbol *clone, *prev, *curr;

	// Duplicate the last symbol copy and mark it, too, as a copy
	clone = (symbol *) malloc(sizeof(symbol));
	memcpy(clone, sym, sizeof(symbol));

	clone->duplicate = true;

	// Seek the end of the symbol list, starting from the input symbol
	prev = curr = sym;
	while(curr->next && curr->next->index == sym->index) {
		prev = curr;
		curr = curr->next;
	}

	// Put the copy into the list
	clone->next = prev->next;
	prev->next = clone;

	return clone;
}


// symbol * clone_symbol (symbol *sym) {
// 	symbol *clone;

// 	clone = clone_symbol(sym);
// 	sym = sym->next;

// 	while(sym) {
// 		clone->next = clone_symbol(sym);
// 		clone = clone->next;
// 		sym = sym->next;
// 	}

// 	return clone;
// }


/**
 * Clone the whole symbol list of the internal representation. This is done
 * in order to support future multiversioning of executable and object files.
 *
 * @return The pointer to the first symbol descriptor of the clone list
 */
/*
static symbol *clone_symbol_list (symbol *sym) {
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
*/

void find_relocations(symbol *symbols, section *in, symbol *to, linked_list *list) {
	symbol *sym, *other;

	ll_node *node, *newnode;
	bool put;

	if (in == NULL || to == NULL || list == NULL) {
		hinternal();
	}

	for (sym = symbols; sym; sym = sym->next) {

		if (sym->sec == in && str_equal(sym->name, to->name)) {

			if (ll_empty(list)) {
				ll_push(list, sym);
			} else {
				put = false;

				for (node = list->first; node; node = node->next) {
					other = node->elem;

					if (other->relocation.offset > sym->relocation.offset) {
						if (node == list->first) {
							ll_push_first(list, sym);
						} else {
							newnode = calloc(sizeof(ll_node), 1);
							newnode->elem = sym;
							newnode->prev = node->prev;
							newnode->next = node;

							newnode->prev->next = newnode;
							newnode->next->prev = newnode;
						}

						put = true;
						break;
					}
				}

				if (put == false) {
					ll_push(list, sym);
				}
			}

		}

	}
}


symbol *symbol_rela_create(symbol *sym, reloc_type type,
	unsigned long long offset, long addend, section *sec) {
	symbol *rela;

	rela = symbol_check_shared(sym);

	sym->referenced = true;

	rela->relocation.addend = addend;
	rela->relocation.offset = offset;
	rela->relocation.sec = sec;
	rela->relocation.target_insn = NULL;

	rela->authentic = false;

	switch(type) {
		case RELOC_PCREL_32:
			rela->relocation.type = R_X86_64_PC32;
			break;

		case RELOC_PCREL_64:
			rela->relocation.type = R_X86_64_PC64;
			break;

		case RELOC_TLSREL_32:
			rela->relocation.type = R_X86_64_TPOFF32;
			break;

		case RELOC_ABS_32:
			rela->relocation.type = R_X86_64_32;
			break;

		case RELOC_ABS_32S:
			rela->relocation.type = R_X86_64_32S;
			break;

		case RELOC_ABS_64:
			rela->relocation.type = R_X86_64_64;
			break;

		default:
			hinternal();
	}

	// if(!strcmp((const char *)secname, ".text")) {

	// 	// Relocatation applies in the .text section towards symbol 'sym'
	// 	switch(sym->type) {
	// 		case SYMBOL_SECTION:
	// 			type = R_X86_64_32;
	// 			break;

	// 		default:
	// 			type = R_X86_64_PC32;
	// 	}
	// } else if(!strcmp((const char *)secname, ".rodata")) {
	// 	// Relocation applies in the .rodata section towards another section symbol
	// 	type = R_X86_64_64;
	// } else {
	// 	// Default value
	// 	type = R_X86_64_64;
	// }

	hnotice(3, "New RELA node [%s] has been created at '%s' + %lld to symbol '%s' + %ld\n",
		reloc_type_str[type], rela->relocation.sec->name, rela->relocation.offset,
			rela->name, rela->relocation.addend);

	return rela;
}


symbol *symbol_rela_create_from_ELF(reloc *rel) {
	symbol *rela;

	rela = symbol_check_shared(rel->sym);

	rel->sym->referenced = true;

	rela->relocation.addend = rel->addend;
	rela->relocation.offset = rel->sec->offset + rel->offset;
	rela->relocation.type = rel->type;
	rela->relocation.sec = rel->sec;

	rela->authentic = false;

	hnotice(3, "New RELA node [%d] has been created at '%s' + <%#08llx> to symbol '%s' + %ld\n",
		rela->relocation.type, rela->relocation.sec->name, rela->relocation.offset,
			rela->name, rela->relocation.addend);

	return rela;
}


/**
 * In order to be linkable, new relocation nodes can be created in case
 * genereted instructions have to be referenced.
 *
 * @param sym Symbol descriptor of the symbol that will be referenced to
 * @param insn The pointer to the descritpor of the instruction who need to be relocated
 */
symbol *symbol_instr_rela_create(symbol *sym, insn_info *insn, reloc_type type) {
	function *func;
	symbol *rela;

	func = find_func_from_instr(insn, NEW_ADDR);

	rela = symbol_check_shared(sym);

	sym->referenced = true;

	// rela->relocation.offset = insn->new_addr + insn->opcode_size - func->symbol->sec->offset;
	rela->relocation.offset = insn->new_addr + insn->opcode_size;
	rela->relocation.sec = func->symbol->sec;

	ll_push(&insn->reference, rela);
	rela->relocation.target_insn = insn;

	rela->authentic = false;

	switch(type) {
		case RELOC_PCREL_32:
		case RELOC_PCREL_64:
			// Recall that the addend is backward and -(a - b) == (b - a)
			rela->relocation.addend = (long)insn->opcode_size - (long)insn->size;
			break;

		// case RELOCATE_ABSOLUTE_32:
		// case RELOCATE_ABSOLUTE_64:
		default:
			rela->relocation.addend = 0;
	}

	switch(type) {
		case RELOC_PCREL_32:
			rela->relocation.type = R_X86_64_PC32;
			break;

		case RELOC_PCREL_64:
			rela->relocation.type = R_X86_64_PC64;
			break;

		case RELOC_TLSREL_32:
			rela->relocation.type = R_X86_64_TPOFF32;
			break;

		case RELOC_ABS_32:
			rela->relocation.type = R_X86_64_32;
			break;

		case RELOC_ABS_32S:
			rela->relocation.type = R_X86_64_32S;
			break;

		case RELOC_ABS_64:
			rela->relocation.type = R_X86_64_64;
			break;

		default:
			hinternal();
	}

	hnotice(3, "New RELA node [%s] has been created at instruction <%#08llx> to symbol '%s' + %ld\n",
		reloc_type_str[type], insn->new_addr, rela->name, rela->relocation.addend);

	return rela;
}


symbol *symbol_rela_clone(symbol *sym) {
	symbol *clone;

	if (sym == NULL) {
		return NULL;
	}

	clone = symbol_check_shared(sym);
	clone->version = PROGRAM(version);

	clone->authentic = false;

	return clone;

	// clone->relocation.offset = sym->relocation.offset;
	// clone->relocation.addend = sym->relocation.addend;
	// clone->relocation.type = sym->relocation.type;
	// clone->relocation.sec = sym->relocation.sec;
}


symbol *symbol_clone(symbol *sym, char *suffix) {
	symbol *clone;
	char *name;

	size_t length;

	if (sym == NULL) {
		return NULL;
	}

	// // Allocates memory for the new descriptor
	// clone = (symbol *) calloc(sizeof(symbol), 1);

	// // Copies the original descriptor to the new one
	// memcpy(clone, sym, sizeof(symbol));

	// // Reset some fields
	// clone->prev = clone->next = NULL;
	// clone->duplicate = true;
	// clone->referenced = true;
	// clone->version = PROGRAM(version);

	clone = symbol_check_shared(sym);
	clone->version = PROGRAM(version);

	clone->relocation.offset = sym->relocation.offset;
	clone->relocation.addend = sym->relocation.addend;
	clone->relocation.type = sym->relocation.type;
	clone->relocation.sec = sym->relocation.sec;

	// Compose the symbol name
	length = strlen((const char *)sym->name) + strlen(suffix) + 2; // one is \0, one is '_'
	name = malloc(sizeof(char) * length);
	bzero(name, length);
	strcpy(name, (const char *)sym->name);
	strcat(name, "_");
	strcat(name, suffix);

	clone->name = name;

	// clone = symbol_create(name, sym->type, sym->bind, sym->sec, sym->size);

	// TODO: What to do with symbols that belong to non-defined sections?
	// clone->secnum = sym->secnum;

	// TODO: Se il simbolo è una funzione, bisogna clonare anche quella?

	// memcpy(&clone->relocation, &sym->relocation, sizeof(struct _relocation));

	return clone;
}
