
#ifndef HANDLE_ELF_
#define HANDLE_ELF_

#include <executable.h>
#include <instruction.h>

/**
 * In order to be linkable, new relocation nodes can be created in case
 * genereted instructions have to be referenced.
 *
 * @param sym Symbol descriptor of the symbol that will be referenced to
 * @param insn The pointer to the descritpor of the instruction who need to be relocated
 */
void create_rela_node (symbol *sym, insn_info *insn);


/**
 * Help in manipulating parsed ELF structure by adding a new symbol node.
 *
 * @param name A pointer to the string that represents the symbol's name
 * @param type The type of the new symbol
 * @param bind The optional binding flag (by default LOCAL binding is used)
 *
 * @return The pointer to the new created symbol descriptor
 */
symbol * create_symbol_node (char *name, int type, int bind);


/**
 * Verifies if the passed symbol is a shared.
 * In case the symbol is shared among multiple relocation
 * entries, then a copy of it will be created in order to save
 * the new offset. During the emit phase, each additional copy
 * of the symbol will be skipped but the relative offset
 * added to a new relocation entry whose the symbol refers to.
 *
 * Note: The function will update the list of symbols by adding
 * the possible duplicate.
 *
 * @param sym Symbol descriptor to check
 *
 * @return The symbol descriptor of the new symbol, or the symbol passed
 * in case no sharing happened.
 */
symbol * symbol_check_shared (symbol *sym);

#endif /* HANDLE_ELF_ */
