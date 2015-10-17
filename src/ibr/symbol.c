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


/**
 * Seeks the symbol descriptor associated with a given symbol name.
 *
 * @param name Buffer pointing to the name of the symbol.
 *
 * @return Pointer to the symbol descriptor found, if any, or <em>NULL</em>.
 */
symbol *find_symbol(unsigned char *name) {
	symbol *sym;

	sym = PROGRAM(symbols);
	while(sym) {
		if(!strcmp((const char *)sym->name, name) && !sym->duplicate)
			return sym;
		sym = sym->next;
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
	unsigned int index;

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

	node->name = (char *) malloc(strlen(name) + 1);
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
		index = sym->index + 1;

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

	hnotice(3, "New %s symbol '%s' (%d) node of type %d and size %d bytes has been created\n",
		node->bind == SYMBOL_LOCAL ? "local" : node->bind == SYMBOL_GLOBAL ?  "global" : "weak", node->name, node->index,
		node->type, node->size);

	return node;
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

	sym->referenced = true;
	hnotice(5, "First reference to '%s'\n", sym->name);
	// no duplicates, return the symbol itself
	return sym;
}


symbol * clone_symbol (symbol *sym) {
	symbol *clone, *head;

	head = clone = clone_symbol(sym);
	sym = sym->next;

	while(sym) {
		clone->next = clone_symbol(sym);
		clone = clone->next;
		sym = sym->next;
	}

	return clone;
}


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

void find_relocations(symbol *symbols, unsigned char *in, unsigned char *to, linked_list *list) {
	symbol *sym, *other;
	unsigned char *secname;

	ll_node *node, *newnode;
	bool put;

	if (in == NULL || to == NULL || list == NULL) {
		hinternal();
	}

	for (sym = symbols; sym; sym = sym->next) {
		secname = sym->relocation.secname;

		if (secname != NULL) {
			if (!strcmp(secname, in) && !strcmp(sym->name, to)) {

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
}
