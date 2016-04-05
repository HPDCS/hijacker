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
* @file version.c
* @brief Module to handle object files
* @author Simone Economo
*/

// This is not a nightmare... it's REAL!
#include <bfd.h>

#include <init.h>
#include <config.h>
#include <ibr.h>


typedef struct object_raw {
	bfd *abfd;
	asymbol **symbols;

	const char *format;
	const char *arch;
} obj_raw_t;


static obj_raw_t orig;


static object_raw_t object_raw_create(const char *path, object_raw_t orig) {
	object_raw_t raw;

	raw = bfd_openw((!path ? DEFAULT_OUT_NAME : path), (orig.abfd)->xvec->name);

	if (!raw) {
		err = bfd_get_error();
		errmsg = bfd_errmsg(err);

		bfd_perror(errmsg);
	}

	// Set object file format
	bfd_set_format(raw, bfd_object);

	// Set architectural info
	bfd_set_arch_info(raw, bfd_get_arch_info(orig.abfd));

	return raw;
}


static object_raw_t object_raw_open(const char *path) {
	object_raw_t raw;

	bfd *abfd;

	bfd_error_type err;
	const char *errmsg;

	if (!path) {
		hinternal();
	}

	bfd_init();

	raw.abfd = bfd_openr(path, NULL);

	if (!raw.abfd) {
		err = bfd_get_error();
		errmsg = bfd_errmsg(err);

		bfd_perror(errmsg);
	}

	// First of all we need to check the object file format
	raw.format = \
		bfd_check_format(raw.abfd, bfd_object) ? bfd_format_string(bfd_object) :
		bfd_check_format(raw.abfd, bfd_archive) ? bfd_format_string(bfd_archive) :
		bfd_check_format(raw.abfd, bfd_core) ? bfd_format_string(bfd_core) :
		"Unrecognised";

	// Now we can fetch architectural info
	raw.arch = bfd_printable_name(raw.abfd);

	return raw;
}


static void object_raw_close(object_raw_t raw) {
	bfd_close(raw.abfd);
}


static obj_format_t object_raw_get_format(object_raw_t *raw) {
	// TODO: To implement
}


static isa_family_t object_raw_get_arch(object_raw_t *raw) {
	// TODO: To implement
}


static void object_raw_load_symbols(object_raw_t *orig, obj_t *obj) {
	asymbol **symbols, *sym;
	size_t nsym, i;

	orig->symbols = symbols = hcalloc(bfd_get_symtab_upper_bound(orig->abfd));

	// Materializes the symbol table in memory
	nsym = bfd_canonicalize_symtab(orig->abfd, symbols);

	for (i = 0; i < nsym; ++i) {
		sym = symbols[i];

		// printf("Symbol `%s` in section `%s`\n",
		// 	sym->name, sym->section->name);

		// printf("\n\t");
		// bfd_print_symbol_vandf(orig.abfd, stdout, sym);
		// printf("\n\n");
	}
}


static void object_raw_load_sections(object_raw_t *orig, obj_t *obj) {
	asection *sec;
	void *payload;

	for (sec = orig.abfd->sections; sec; sec = sec->next) {
		// printf("Section `%s` of size %d bytes\n",
		// 	sec->name, sec->size);

		payload = hmalloc(sec->size);

		bfd_get_section_contents(orig.abfd, sec, payload, 0, sec->size);

		// printf("\n");
		// hexdump(payload, sec->size);
		// printf("\n");
	}
}


static void object_raw_load_relocs(object_raw_t *orig, obj_t *obj) {
	arelent **relocs, *rel;
	size_t nrel, i;

	for (sec = orig.abfd->sections; sec; sec = sec->next) {
		relocs = hmalloc(bfd_get_reloc_upper_bound(orig.abfd, sec));

		// Materializes relocations in memory
		nrel = bfd_canonicalize_reloc(orig.abfd, sec, relocs, orig->symbols);

		for (i = 0; i < nrel; ++i) {
			rel = relocs[i];

			// printf("Relocation in section `%s` at %p to symbol '%s' +%p\n",
			// 	sec->name, rel->address, (*rel->sym_ptr_ptr)->name, rel->addend);

			// printf("\n\t%s\t%s\n\n", rel->howto->name, bfd_get_reloc_code_name(rel->howto->type));
		}
	}
}


static void object_raw_write_symbol(object_raw_t new, sym_t *symbol) {
	asymbol *sym = bfd_make_empty_symbol(newbfd);
	sym->name = "come_se_fosse";
	sym->section = sec;
	sym->flags = BSF_GLOBAL;
	sym->value = 0x12345;

	asymbol *symtab[2];
	symtab[0] = sym;
	symtab[1] = NULL;

	bfd_set_symtab(newbfd, symtab, 1);
}


static void object_raw_write_section(object_raw_t new, sec_t *section) {
	asection *sec = bfd_make_section_with_flags(
		newbfd, ".antani", SEC_DATA | SEC_ALLOC | SEC_HAS_CONTENTS | SEC_RELOC);

	if (sec == NULL) {
		err = bfd_get_error();
		errmsg = bfd_errmsg(err);

		bfd_perror(errmsg);
	}

	sec->size = 1024;
}


static void object_raw_write_reloc(object_raw_t new, rel_t *reloc) {
	arelent *rel = malloc(sizeof(arelent));
	rel->address = 0x55;
	rel->addend = -4;
	rel->sym_ptr_ptr = &sym;
	rel->howto = bfd_reloc_type_lookup(newbfd, BFD_RELOC_32_PCREL);

	arelent *reltab[2];
	reltab[0] = rel;
	reltab[1] = NULL;

	bfd_set_reloc(newbfd, sec, reltab, 1);

	object_raw_close(orig);
	object_raw_close(new);
}


void object_load(const char *path) {
	ver_t *zero;

	orig = object_raw_open(path);

	__PROGRAM__(format) = object_raw_get_format(&orig);
	__PROGRAM__(arch) = object_raw_get_arch(&orig);

	// SYMBOLS
	// ---------------------------------------------
	object_raw_load_symbols(&orig, &config.program);

	// SECTIONS
	// ---------------------------------------------
	object_raw_load_sections(&orig, &config.program);

	// RELOCATIONS
	// ---------------------------------------------
	object_raw_load_relocs(&orig, &config.program);

	// Create initial version and parse it into the high-level IBR
	zero = version_create("__orig__");
}


void object_write(const char *path) {
	object_raw_t new;

	list_node_t *node;
	size_t vnumber;

	ver_t *version;
	sym_t *symbol;
	sec_t *section;
	rel_t *reloc;

	new = object_raw_create(path, orig);

	version_for_each(vnumber, version) {

		// SYMBOLS
		// ---------------------------------------------
		list_for_each(&__VERSION__(symbols), node) {
			symbol = node->elem;

			object_raw_write_symbol(new, symbol);
		}

		// SECTIONS
		// ---------------------------------------------
		list_for_each(&__VERSION__(sections), node) {
			section = node->elem;

			object_raw_write_section(new, section);
		}

		// RELOCATIONS
		// ---------------------------------------------
		list_for_each(&__VERSION__(relocs), node) {
			reloc = node->elem;

			object_raw_write_reloc(new, reloc);
		}

	}



}
