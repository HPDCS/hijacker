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
* @file parse-elf.c
* @brief Transforms an ELF object file in the hijacker's intermediate representation
* @author Alessandro Pellegrini
* @author Davide Cingolani
* @date September 19, 2008
*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <string.h>

#include <hijacker.h>
#include <prints.h>
#include <instruction.h>
#include <utils.h>

#include "elf-defs.h"
#include "handle-elf.h"


#if 0
bool dump_elf(elf_file *elf, char *new_path) {

	unsigned int 	i;
	int		count = 0,	// Per assicurare la scrittura completa
			offset = 0;	// Per ricalcolare gli offset nel file

	// Se richiesto, crea il nuovo file
	if(new_path != NULL) {
		close(ELF(pointer));
		ELF(pointer) = creat(new_path, 0775);
		if(ELF(pointer) == -1) {
			fprintf(stderr, "Errore nella creazione del file %s\n", new_path);
			return false;
		}
	}

	lseek(ELF(pointer), 0L, SEEK_SET);

	// Calcola dove andrà a cadere la section header table
	if(ELF(is64))	// Dopo l'header dell'ELF
		offset = sizeof(Elf64_Ehdr);
	else
		offset = sizeof(Elf32_Ehdr);

	for(i = 0; i < ELF(secnum); i++) {	// Dopo tutte le sezioni
		if(ELF(is64))
			offset += ELF(sec_hdr)[i]->section64.sh_size;
		else
			offset += ELF(sec_hdr)[i]->section32.sh_size;
	}

	// Scrive l'header del file ELF
	if(ELF(is64)) {
		ELF(hdr)->header64.e_shoff = offset;
		do {
			if((count += write(ELF(pointer), ELF(hdr) + count, sizeof(Elf64_Ehdr) - count)) == -1) {
				fprintf(stderr, "Errore nella scrittura dell'header dell'ELF\n");
				return false;
			}
		} while(count != sizeof(Elf64_Ehdr));
		offset = sizeof(Elf64_Ehdr);
	} else {
		ELF(hdr)->header32.e_shoff = offset;
		do {
			if((count += write(ELF(pointer), ELF(hdr) + count, sizeof(Elf32_Ehdr) - count)) == -1) {
				fprintf(stderr, "Errore nella creazione dell'header dell'ELF\n");
				return false;
			}
		} while(count != sizeof(Elf32_Ehdr));
		offset = sizeof(Elf32_Ehdr);
	}

	// Scrive tutte le sezioni
	for(i = 0; i < ELF(secnum); i++) {
		count = 0;
		if(ELF(is64)) {
			do {
				if((count += write(ELF(pointer), ELF(sections)[i] + count, ELF(sec_hdr)[i]->section64.sh_size - count)) == -1) {
					fprintf(stderr, "Errore nella scrittura della %d sezione\n", i);
					return false;
				}
			} while(count != (int)ELF(sec_hdr)[i]->section64.sh_size);
		} else {
			do {
				if((count += write(ELF(pointer), ELF(sections)[i] + count, ELF(sec_hdr)[i]->section32.sh_size - count)) == -1) {
					fprintf(stderr, "Errore nella scrittura della %d sezione\n", i);
					return false;
				}
			} while(count != (int)ELF(sec_hdr)[i]->section32.sh_size);
		}
	}

	// Scrive gli header di tutte le sezioni
	for(i = 0; i < ELF(secnum); i++) {
		count = 0;
		if(ELF(is64)) {

			// Corregge l'offset della sezione
			if(i != 0) { // L'entry 0 non va corretta!
				ELF(sec_hdr)[i]->section64.sh_offset = offset;
				offset += ELF(sec_hdr)[i]->section64.sh_size;
			}

			do {
				if((count += write(ELF(pointer), ELF(sec_hdr)[i] + count, ELF(hdr)->header64.e_shentsize - count)) == -1) {
					fprintf(stderr, "Errore nella scrittura dell'header della %d sezione\n", i);
					return false;
				}
			} while(count != ELF(hdr)->header64.e_shentsize);
		} else {

			// Corregge l'offset della sezione
			if(i != 0) {
				ELF(sec_hdr)[i]->section32.sh_offset = offset;
				offset += ELF(sec_hdr)[i]->section32.sh_size;
			}

			do {
				if((count += write(ELF(pointer), ELF(sec_hdr)[i] + count, ELF(hdr)->header32.e_shentsize - count)) == -1) {
					fprintf(stderr, "Errore nella scrittura dell'header della %d sezione\n", i);
					return false;
				}
			} while(count != ELF(hdr)->header32.e_shentsize);
		}
	}

	// Il file è stato salvato
	ELF(edited) = false;

	return true;
}

inline bool ignore_section(elf_file *elf, unsigned int sec) {

	int i = -1;
	char *ignore[] = {".interp", ".plt", ".stab", ".comment", ".sbbs", ".shstrtab",
			".stabstr", ".got", ".dtors", ".dynstr", ".ctors", ".eh_frame",
			".debug", NULL};

	char *name = get_section_name(elf, sec);

	// Controlla se la sezione è da ignorare
	while(ignore[++i] != NULL) {
		if(strcmp(name, ignore[i]) == 0)
			return true;
	}

	// La sezione non va ignorata
	return false;
}


inline bool is_executable(elf_file *elf, unsigned int sec) {

	if(ELF(is64)) {
		if(ELF(sec_hdr)[sec]->section64.sh_flags & SHF_EXECINSTR)
			return true;
	} else {
		if(ELF(sec_hdr)[sec]->section32.sh_flags & SHF_EXECINSTR)
			return true;
	}

	return false;

}

inline void increment_section_size(elf_file *elf, unsigned int sec, int increment) {

	if(ELF(is64))
		ELF(sec_hdr)[sec]->section64.sh_size += increment;
	else
		ELF(sec_hdr)[sec]->section32.sh_size += increment;

	// Il file è stato modificato
	ELF(edited) = true;

}

inline int get_rel_section_type(elf_file *elf, unsigned int sec) {

	unsigned int i;
	int rel_type;

	for(i = 0; i < ELF(secnum); i++) {
		rel_type = is_relocation_table(elf, i);
		if(rel_type != NO_REL) {
			if(ELF(is64)) {
				if(ELF(sec_hdr)[i]->section64.sh_info == sec) 
					return rel_type;
			} else {
				if(ELF(sec_hdr)[i]->section32.sh_info == sec)
					return rel_type;
			}
		}
	}

	return NO_REL;
}

static void shift_reloc_entry_rela(elf_file *elf, unsigned int sec, unsigned int old_offset, int shift) {

	int pos = 0, sec_size;
	Elf_Rela *reloc;

	// Determina la dimensione della sezione di rilocazione
	if(ELF(is64))
		sec_size = ELF(sec_hdr)[sec]->section64.sh_size;
	else
		sec_size = ELF(sec_hdr)[sec]->section32.sh_size;

	// Scandisce tutte le entry di rilocazione alla ricerca di quelle con
	// offset maggiore di old_offset
	while(pos < sec_size) {

		// Punta alla sezione corrente
		reloc = (Elf_Rela *)(ELF(sections)[sec] + pos);

		if(ELF(is64)) {
			// Controlla se è da aggiornare
			if(reloc->rel64.r_offset >= old_offset)
				reloc->rel64.r_offset += shift;

			// Avanza nella sezione
			pos += sizeof(Elf64_Rela);
		} else {
			// Controlla se è da aggiornare
			if(reloc->rel32.r_offset >= old_offset)
				reloc->rel32.r_offset += shift;

			// Avanza nella sezione
			pos += sizeof(Elf32_Rela);
		}
	}
}

static void shift_reloc_entry_rel(elf_file *elf, unsigned int sec, unsigned int old_offset, int shift) {

	int pos = 0, sec_size;
	Elf_Rel *reloc;

	// Determina la dimensione della sezione di rilocazione
	if(ELF(is64))
		sec_size = ELF(sec_hdr)[sec]->section64.sh_size;
	else
		sec_size = ELF(sec_hdr)[sec]->section32.sh_size;

	// Scandisce tutte le entry di rilocazione alla ricerca di quelle con
	// offset maggiore di old_offset
	while(pos < sec_size) {

		// Punta alla sezione corrente
		reloc = (Elf_Rel *)(ELF(sections)[sec] + pos);

		if(ELF(is64)) {
			// Controlla se è da aggiornare
			if(reloc->rel64.r_offset >= old_offset)
				reloc->rel64.r_offset += shift;

			// Avanza nella sezione
			pos += sizeof(Elf64_Rel);
		} else {
			// Controlla se è da aggiornare
			if(reloc->rel32.r_offset >= old_offset)
				reloc->rel32.r_offset += shift;

			// Avanza nella sezione
			pos += sizeof(Elf32_Rel);
		}
	}
}

char *get_symbol_name_by_reloc_position(elf_file *elf, unsigned int offset, unsigned int sec) {

	Elf32_Rel *rel32;
	Elf32_Rela *rela32;
	Elf64_Rel *rel64;
	Elf64_Rela *rela64;

	Elf32_Sym *sym32;
	Elf64_Sym *sym64;

	unsigned int 	reloc_sec,
	reloc_size;
	int	reloc_type,
	symbol_position,
	symbol_tab,
	symbol_name_position,
	symbol_name_table;
	unsigned int pos = 0;

	// Trova la sezione di rilocazione per la sezione sec
	for(reloc_sec = 0; reloc_sec < ELF(secnum); reloc_sec++) {

		// Determina se è una sezione di rilocazione, e di che tipo
		reloc_type = is_relocation_table(elf, reloc_sec);
		if(reloc_type == NO_REL)
			continue;


		if(ELF(is64)) {
			// Per le sezioni di rilocazione il campo sh_info
			// contiene l'indice cui si riferisce la rilocazione
			if(ELF(sec_hdr)[reloc_sec]->section64.sh_info == sec) {
				break;
			}
		} else {
			// Per le sezioni di rilocazione il campo sh_info
			// contiene l'indice cui si riferisce la rilocazione
			if(ELF(sec_hdr)[reloc_sec]->section32.sh_info == sec) {
				break;
			}
		}
	}

	// Determina la dimensione della sezione di rilocazione
	if(ELF(is64))
		reloc_size = ELF(sec_hdr)[reloc_sec]->section64.sh_size;
	else
		reloc_size = ELF(sec_hdr)[reloc_sec]->section32.sh_size;

	// All'interno della sezione di rilocazione cerca un simbolo il
	// cui offset coincida con quello passato
	while(pos < reloc_size) {
		if(ELF(is64)) {
			if(reloc_type == IS_REL) {

				// Recupera l'entry di rilocazione e controlla
				// se l'offset è coincidente
				rel64 = (Elf64_Rel *)(ELF(sections)[reloc_sec] + pos);
				if(rel64->r_offset == offset)
					break;

				// Passa all'elemento successivo
				pos += sizeof(Elf64_Rel);

			} else if(reloc_type == IS_RELA) {

				// Recupera l'entry di rilocazione e controlla
				// se l'offset è coincidente
				rela64 = (Elf64_Rela *)(ELF(sections)[reloc_sec] + pos);
				if(rela64->r_offset == offset)
					break;

				// Passa all'elemento successivo
				pos += sizeof(Elf64_Rela);

			} else {
				fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
				return NULL;
			}
		} else {
			if(reloc_type == IS_REL) {

				// Recupera l'entry di rilocazione e controlla
				// se l'offset è coincidente
				rel32 = (Elf32_Rel *)(ELF(sections)[reloc_sec] + pos);
				if(rel32->r_offset == offset)
					break;

				// Passa all'elemento successivo
				pos += sizeof(Elf32_Rel);

			} else if(reloc_type == IS_RELA) {

				// Recupera l'entry di rilocazione e controlla
				// se l'offset è coincidente
				rela32 = (Elf32_Rela *)(ELF(sections)[reloc_sec] + pos);
				if(rela32->r_offset == offset)
					break;

				// Passa all'elemento successivo
				pos += sizeof(Elf32_Rela);

			} else {
				fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
				return NULL;
			}
		}
	}

	// Controllo per vedere se effettivamente l'entry di rilocazione era presente
	if(pos >= reloc_size)
		return NULL;

	// Recupera la posizione del nome del simbolo nella tabella dei nomi dei simboli
	if(ELF(is64)) {
		if(reloc_type == IS_REL)
			symbol_position = ELF64_R_SYM(rel64->r_info);
		else if(reloc_type == IS_RELA)
			symbol_position = ELF64_R_SYM(rela64->r_info);
		else {
			fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
			return NULL;
		}
	} else {
		if(reloc_type == IS_REL)
			symbol_position = ELF32_R_SYM(rel32->r_info);
		else if(reloc_type == IS_RELA)
			symbol_position = ELF32_R_SYM(rela32->r_info);
		else {
			fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
			return NULL;
		}
	}

	// Recupera la sezione con i simboli
	if(ELF(is64))
		symbol_tab = ELF(sec_hdr)[reloc_sec]->section64.sh_link;
	else
		symbol_tab = ELF(sec_hdr)[reloc_sec]->section32.sh_link;

	// Punta al simbolo relativo alla rilocazione e ne recupera la posizione del nome
	if(ELF(is64)) {
		sym64 = (Elf64_Sym *)(ELF(sections)[symbol_tab] + (symbol_position * sizeof(Elf64_Sym)));
		symbol_name_position = sym64->st_name;
	} else {
		sym32 = (Elf32_Sym *)(ELF(sections)[symbol_tab] + (symbol_position * sizeof(Elf32_Sym)));
		symbol_name_position = sym32->st_name;
	}

	// Recupera la sezione con i nomi dei simboli
	if(ELF(is64))
		symbol_name_table = ELF(sec_hdr)[symbol_tab]->section64.sh_link;
	else
		symbol_name_table = ELF(sec_hdr)[symbol_tab]->section32.sh_link;

	// Punta alla stringa rappresentante il nome
	return (char *)(ELF(sections)[symbol_name_table] + symbol_name_position);
}



void shift_functions(elf_file *elf, unsigned int starting_position, int shift) {

	unsigned int i, pos = 0, sec_size;
	Elf32_Sym *sym32;
	Elf64_Sym *sym64;

	// Trova la sezione con i simboli
	for(i = 0; i < ELF(secnum); i++) {
		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_SYMTAB) {
				sym64 = (Elf64_Sym *)ELF(sections)[i];
				break;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_SYMTAB) {
				sym32 = (Elf32_Sym *)ELF(sections)[i];
				break;
			}
		}
	}

	// Scandisce la SymTab alla ricerca delle funzioni da rilocare
	if(ELF(is64))
		sec_size = ELF(sec_hdr)[i]->section64.sh_size;
	else
		sec_size = ELF(sec_hdr)[i]->section32.sh_size;

	while(pos < sec_size) {

		if(ELF(is64)) {
			if(ELF64_ST_TYPE(sym64->st_info) == STT_FUNC || (ELF64_ST_TYPE(sym64->st_info) == STT_NOTYPE && ELF64_ST_BIND(sym64->st_info) == STB_LOCAL)) {
				if(sym64->st_value >= starting_position)
					sym64->st_value += shift;
			}

			sym64 += 1;
			pos += sizeof(Elf64_Sym);
		} else {
			if(ELF32_ST_TYPE(sym32->st_info) == STT_FUNC || (ELF32_ST_TYPE(sym32->st_info) == STT_NOTYPE && ELF32_ST_BIND(sym32->st_info) == STB_LOCAL)) {
				if(sym32->st_value >= starting_position) {
					sym32->st_value += shift;
				}
			}

			sym32 += 1;
			pos += sizeof(Elf32_Sym);
		}
	}
}




void shift_reloc_entry(elf_file *elf, unsigned int sec, unsigned int old_offset, int shift) {

	unsigned int i;
	int reloc_type;

	// Riloca i riferimenti a funzioni
	shift_functions(elf, old_offset, shift);

	// Trova la sezione di rilocazione per la sezione sec
	for(i = 0; i < ELF(secnum); i++) {

		// Determina se è una sezione di rilocazione, e di che tipo
		reloc_type = is_relocation_table(elf, i);
		if(reloc_type == NO_REL)
			continue;


		if(ELF(is64)) {
			// Per le sezioni di rilocazione il campo sh_info
			// contiene l'indice cui si riferisce la rilocazione
			if(ELF(sec_hdr)[i]->section64.sh_info == sec) {
				if(reloc_type == IS_REL)
					shift_reloc_entry_rel(elf, i, old_offset, shift);
				else if(reloc_type == IS_RELA)
					shift_reloc_entry_rela(elf, i, old_offset, shift);
				else
					fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
			}
		} else {
			// Per le sezioni di rilocazione il campo sh_info
			// contiene l'indice cui si riferisce la rilocazione
			if(ELF(sec_hdr)[i]->section32.sh_info == sec) {
				if(reloc_type == IS_REL)
					shift_reloc_entry_rel(elf, i, old_offset, shift);
				else if(reloc_type == IS_RELA)
					shift_reloc_entry_rela(elf, i, old_offset, shift);
				else
					fprintf(stderr, "%s: errore interno alla riga %d\n", __FILE__, __LINE__);
			}
		}
	}

	// Il file è stato modificato
	ELF(edited) = true;
}

void writeable_section(elf_file *elf, char *sec_name) {

	unsigned int i;

	// Cerca la sezione
	for(i = 0; i < ELF(secnum); i++) {
		char *string_name = get_section_name(elf, i);

		if(strcmp(string_name, sec_name) == 0)
			break;
	}

	// È stata davvero trovata la sezione?!
	if(i == ELF(secnum)) {
		fprintf(stderr, "Non è stata trovata la sezione %s\n", sec_name);
		return;
	}

	// Aggiunge il flag di scrittura alla sezione
	if(ELF(is64))
		ELF(sec_hdr)[i]->section64.sh_flags |= SHF_WRITE;
	else
		ELF(sec_hdr)[i]->section32.sh_flags |= SHF_WRITE;

	// Il file è stato modificato
	//ELF(edited) = true;

}

void rename_symbol(elf_file *elf, char *old_name, char *new_name) {

	unsigned int i;

	int 	totale = 0,
			trovato = 0,
			limite = -1;

	char 	*str_tab,
	*corrente;

	// I nomi delle stringhe devono avere la stessa lunghezza!
	if(strlen(old_name) != strlen(new_name)) {
		fprintf(stderr, "Errore: le stringhe passate non hanno la stessa lunghezza! [%s - %s]\n", old_name, new_name);
		exit(-1);
	}

	// Trova la sezione con i simboli
	for(i = 0; i < ELF(secnum); i++) {
		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_STRTAB) 
				limite = ELF(sec_hdr)[i]->section64.sh_size;
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_STRTAB) 
				limite = (int)ELF(sec_hdr)[i]->section32.sh_size;
		}

		if (limite == -1)
			continue;

		str_tab = (char *)ELF(sections)[i];
		corrente = str_tab;

		while (strcmp(corrente, old_name) != 0 && totale < limite) {
			if (strlen(corrente) == 0)
				totale += 1;
			else
				totale += strlen(corrente);

			corrente = str_tab + totale + 1;
		}

		if (strcmp(corrente, old_name) == 0) {
			trovato = 1;
			//			printf("Coping %s in %s\n", new_name, corrente);
			strcpy(corrente, new_name);
			ELF(edited) = 1;
		}
		limite = -1;
		totale= 0; //Alice
	}

	if (trovato == 0) {
		printf("Rename_symbol: Simbolo non trovato impossibile sostituire\n");
		fflush(stdout);
	}


}

int num_functions_to_rename(elf_file *elf) {

	unsigned int 	i,
	pos = 0,
	count = 0,
	sec_size;
	Elf32_Sym *sym32;
	Elf64_Sym *sym64;

	// Trova la sezione con i simboli
	for(i = 0; i < ELF(secnum); i++) {
		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_SYMTAB) {
				sym64 = (Elf64_Sym *)ELF(sections)[i];
				break;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_SYMTAB) {
				sym32 = (Elf32_Sym *)ELF(sections)[i];
				break;
			}
		}

	}
	// Scandisce la SymTab alla ricerca delle funzioni da rilocare
	if(ELF(is64))
		sec_size = ELF(sec_hdr)[i]->section64.sh_size;
	else
		sec_size = ELF(sec_hdr)[i]->section32.sh_size;

	while(pos < sec_size) {

		if(ELF(is64)) {
			if(ELF64_ST_TYPE(sym64->st_info) == STT_FUNC) {
				if(ELF64_ST_TYPE(sym64->st_shndx) != SHN_UNDEF) 
					count++;
			}

			sym64 += 1;
			pos += sizeof(Elf64_Sym);
		} else {
			if(ELF32_ST_TYPE(sym32->st_info) == STT_FUNC) {
				if(ELF32_ST_TYPE(sym32->st_shndx) != SHN_UNDEF) 
					count++;
			}

			sym32 += 1;
			pos += sizeof(Elf32_Sym);
		}
	}

	return count;
}

unsigned int *functions_indices(elf_file *elf, int *num_renames, int length) {

	unsigned int 	i,
	*indices;
	int	j,
	h,
	pos = 0,
	sec_size,
	temp,
	index = 0,
	to_rename = 0;

	Elf32_Sym *sym32;
	Elf64_Sym *sym64;

	indices = (unsigned int *)malloc(*num_renames * sizeof(unsigned int));

	// Trova la sezione con i simboli
	for(i = 0; i < ELF(secnum); i++) {
		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_SYMTAB) {
				sym64 = (Elf64_Sym *)ELF(sections)[i];
				break;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_SYMTAB) {
				sym32 = (Elf32_Sym *)ELF(sections)[i];
				break;
			}
		}

	}
	// Scandisce la SymTab alla ricerca delle funzioni da rilocare
	if(ELF(is64))
		sec_size = ELF(sec_hdr)[i]->section64.sh_size;
	else
		sec_size = ELF(sec_hdr)[i]->section32.sh_size;

	while(pos < sec_size) {

		if(ELF(is64)) {
			if(ELF64_ST_TYPE(sym64->st_info) == STT_FUNC) {
				if(ELF64_ST_TYPE(sym64->st_shndx) != SHN_UNDEF) {
					indices[index++] = sym64->st_name;
					to_rename++;
				}
			}

			sym64 += 1;
			pos += sizeof(Elf64_Sym);
		} else {
			if(ELF32_ST_TYPE(sym32->st_info) == STT_FUNC) {
				if(ELF32_ST_TYPE(sym32->st_shndx) != SHN_UNDEF) { 
					indices[index++] = sym32->st_name;
					to_rename++;
				}
			}

			sym32 += 1;
			pos += sizeof(Elf32_Sym);
		}
	}

	*num_renames = to_rename;
	for (h = 0; h < *num_renames; h++)
		for (j = h + 1; j < *num_renames; j++)
			if (indices[j] < indices[h]) {
				temp = indices[h];
				indices [h] = indices[j];
				indices[j] = temp;
			}

	pos = 0;
	if(ELF(is64)) {
		if(ELF(sec_hdr)[i]->section64.sh_type == SHT_SYMTAB) {
			sym64 = (Elf64_Sym *)ELF(sections)[i];
		}
	} else {
		if(ELF(sec_hdr)[i]->section32.sh_type == SHT_SYMTAB) {
			sym32 = (Elf32_Sym *)ELF(sections)[i];
		}
	}
	while(pos < sec_size) {

		if(ELF(is64)) {
			index = 0;
			while (sym64->st_name > indices[index]) {
				if (index < to_rename - 1)
					index++;
				else {
					index++;
					break;
				}
			}
			sym64->st_name += index * length;

			sym64 += 1;
			pos += sizeof(Elf64_Sym);
		} else {
			index = 0;
			while (sym32->st_name > indices[index]) {
				if (index < to_rename - 1)
					index++;
				else {
					index++;
					break;
				}
			}
			sym32->st_name += index * length;

			sym32 += 1;
			pos += sizeof(Elf32_Sym);
		}
	}

	return indices;
}

void rename_def_functions(elf_file *elf) {

	unsigned int	i,
	*indices;
	int	j,
	limite,
	copied = 0,
	addition,
	string_length,
	sezioni_trovate = 0,
	length;

	char	*str_tab,
	*old_strtab,
	*current_strtab,
	*new_strtab,
	*string_tail;

	string_length = strlen("_light");
	string_tail = (char *)malloc(string_length);
	string_tail = "_light";
	addition = num_functions_to_rename(elf);
	if (addition == 0)
		return;
	indices = functions_indices(elf, &addition, string_length);

	// Trova la sezione con i simboli
	for(i = 0; i < ELF(secnum); i++) {
		limite = -1;
		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_STRTAB) 
				limite = ELF(sec_hdr)[i]->section64.sh_size;
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_STRTAB) 
				limite = ELF(sec_hdr)[i]->section32.sh_size;
		}

		if (limite == -1)
			continue;	// TODO: ??????????
		if (sezioni_trovate == 0) {
			sezioni_trovate++;
			continue;
		}

		str_tab = (char *)ELF(sections)[i];
		new_strtab = (char *)malloc(limite + addition * string_length);

		current_strtab = new_strtab;
		old_strtab = str_tab;
		copied = 0;
		j = 0;
		while (copied < limite) {
			length = strlen(old_strtab);
			if (length == 0) {
				current_strtab += 1;
				old_strtab += 1;
				copied += 1;
				continue;
			}
			strcpy(current_strtab, old_strtab);
			if ( j < addition) {
				if (copied == (int)indices[j]) {
					j++;
					strcat(current_strtab, string_tail);
				}
			}
			current_strtab += strlen(current_strtab) + 1;
			old_strtab += strlen(old_strtab) + 1;
			copied += (length + 1);
		}

		ELF(sections)[i] = (unsigned char *)new_strtab;

		// controllare che ci può essere solo una string table per elf file
		ELF(edited) = 1;
		break;
	}

	/*
	Ristampare per debugging tutta la nuova string table
	int pos = 0;
	current_strtab = new_strtab;
	printf("Nuova tabella delle stringh\n");
	fflush(stdout);
	while (pos < limite + addition * string_length) {
		if (strlen(current_strtab) == 0) {
			current_strtab += 1;
			pos++;
			continue;	
		}
		printf("%s\n", current_strtab);
		pos += strlen(current_strtab) + 1;
		current_strtab += strlen(current_strtab) + 1;
	} 
	 */
	increment_section_size(elf, i, addition * string_length);

}

void rename_section(elf_file *elf, char *old_name, char *new_name) {

	unsigned int i;

	// I nomi delle stringhe devono avere la stessa lunghezza!
	if(strlen(old_name) != strlen(new_name)) {
		fprintf(stderr, "Errore: le stringhe passate non hanno la stessa lunghezza! [%s - %s]\n", old_name, new_name);
		exit(-1);
	}

	// Cerca la stringa e la sostituisce
	for(i = 0; i < ELF(secnum); i++) {
		char *string_name = get_section_name(elf, i);

		if(strcmp(string_name, old_name) == 0) {
			strcpy(string_name, new_name);
			return;
		}
	}

}

bool load_section(elf_file *elf, unsigned int sec) {

	if(ELF(is64)) {
		// Crea lo spazio per l'i-simo header delle sezioni
		ELF(sec_hdr)[sec] = malloc(ELF(hdr)->header64.e_shentsize);
		if(ELF(sec_hdr)[sec] == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per l'header della %d sezione\n", sec);
			return false;
		}

		// Carica l'header i-simo
		lseek(ELF(pointer), ELF(hdr)->header64.e_shoff + sec * ELF(hdr)->header64.e_shentsize, SEEK_SET);
		if(read(ELF(pointer), ELF(sec_hdr)[sec], ELF(hdr)->header64.e_shentsize) != ELF(hdr)->header64.e_shentsize) {
			fprintf(stderr, "Impossibile caricare l'header della %d sezione\n", sec);
			return false;
		}

		// Crea lo spazio per la sezione i-sima
		ELF(sections)[sec] = malloc(ELF(sec)_hdr[sec]->section64.sh_size);
		if(ELF(sections)[sec] == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per la %d sezione\n", sec);
			return false;
		}

		// Caricala sezione i-sima
		lseek(ELF(pointer), ELF(sec_hdr)[sec]->section64.sh_offset, SEEK_SET);
		if((unsigned int)read(ELF(pointer), ELF(sections)[sec], ELF(sec_hdr)[sec]->section64.sh_size) != ELF(sec_hdr)[sec]->section64.sh_size) {
			fprintf(stderr, "Impossibile caricare la %d sezione\n", sec);
			return false;
		}
	} else {
		// Crea lo spazio per l'i-simo header delle sezioni
		ELF(sec_hdr)[sec] = malloc(ELF(hdr)->header32.e_shentsize);
		if(ELF(sec_hdr)[sec] == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per l'header della %d sezione\n", sec);
			return false;
		}

		// Carica l'header i-simo
		lseek(ELF(pointer), ELF(hdr)->header32.e_shoff + sec * ELF(hdr)->header32.e_shentsize, SEEK_SET);
		if(read(ELF(pointer), ELF(sec_hdr)[sec], ELF(hdr)->header32.e_shentsize) != ELF(hdr)->header32.e_shentsize) {
			fprintf(stderr, "Impossibile caricare l'header della %d sezione\n", sec);
			return false;
		}

		// Crea lo spazio per la sezione i-sima
		ELF(sections)[sec] = malloc(ELF(sec_hdr)[sec]->section32.sh_size);
		if(ELF(sections)[sec] == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per la %d sezione\n", sec);
			return false;
		}

		// Caricala sezione i-sima
		lseek(ELF(pointer), ELF(sec_hdr)[sec]->section32.sh_offset, SEEK_SET);
		if(read(ELF(pointer), ELF(sections)[sec], ELF(sec_hdr)[sec]->section32.sh_size) != ELF(sec_hdr)[sec]->section32.sh_size) {
			printf("richiesti: %d\n", ELF(sec_hdr)[sec]->section32.sh_size);
			fprintf(stderr, "Impossibile caricare la %d sezione\n", sec);
			return false;
		}
	}

	return true;
}

bool load_elf_header(elf_file *elf) {

	lseek(ELF(pointer), 0L, SEEK_SET);

	if(ELF(is64)) {
		// Crea lo spazio in memoria per l'header
		ELF(hdr) = malloc(sizeof(Elf64_Ehdr));
		if(ELF(hdr) == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per l'header dell'ELF\n");
			return false;
		}
		// Carica l'header
		if(read(ELF(pointer), ELF(hdr), sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
			fprintf(stderr, "Errore nella lettura dell'header dell'ELF");
			return false;
		}
	} else {
		// Crea lo spazio in memoria per l'header
		ELF(hdr) = malloc(sizeof(Elf32_Ehdr));
		if(ELF(hdr) == NULL) {
			fprintf(stderr, "Errore nell'allocazione della memoria per l'header dell'ELF\n");
			return false;
		}
		// Carica l'header
		if(read(ELF(pointer), ELF(hdr), sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)) {
			fprintf(stderr, "Errore nella lettura dell'header dell'ELF");
			return false;
		}
	}

	return true;
}


bool load_elf(elf_file *elf, char *path) {

	unsigned int sec;

	// Tenta l'apertura del file
	ELF(pointer) = open(path, O_RDWR);
	if(ELF(pointer) == -1) {
		fprintf(stderr, "Impossibile aprire il file %s\n", path);
		return false;
	}

	// Carica l'header dell'ELF
	if(!load_elf_header(elf))
		return false;

	// Determina il numero di sezioni
	if(ELF(is64))
		ELF(secnum) = ELF(hdr)->header64.e_shnum;
	else
		ELF(secnum) = ELF(hdr)->header32.e_shnum;

	// Carica tutte le sezioni
	ELF(sec_hdr) = malloc(ELF(secnum) * sizeof(Section_Hdr *));
	ELF(sections) = malloc(ELF(secnum) * sizeof(char *));

	for(sec = 0; sec < ELF(secnum); sec++) {
		if(!load_section(elf, sec))
			return false;
	}

	// Il file non è stato modificato
	ELF(edited) = false;

	return true;

}

void close_elf(elf_file *elf) {

	// Scrive le modifiche se necessario
	if(ELF(edited))
		dump_elf(elf, NULL);

	// Chiude il file
	close(ELF(pointer));

}


int count_symbol(elf_file *elf, char* name){

	unsigned int 	i;
	int	totale = 0,
			limite = -1,
			counter = 0;


	char 	*str_tab,
	*corrente;


	for(i = 0; i < ELF(secnum); i++) {

		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_STRTAB) {

				limite = (int)ELF(sec_hdr)[i]->section64.sh_size;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_STRTAB)
				limite = (int)ELF(sec_hdr)[i]->section32.sh_size;
		}



		if (limite == -1)
			continue;

		str_tab = (char *)ELF(section)s[i] - 1;
		corrente = str_tab;

		while (totale < limite) {

			if (strstr(corrente, name) != NULL) { // Se trovo il simbolo...

				counter++;

			}

			if (strlen(corrente) == 0)
				totale += 1;
			else
				totale += strlen(corrente);

			corrente = str_tab + totale + 1;

		}

		limite = -1;
		totale= 0;
	}


	printf("Occorrenze del simbolo %s = %d\n", name, counter);

	return counter;

}


unsigned long find_symbol(elf_file *elf, char* name, int occurrences) {


	unsigned int 	i;
	int	totale = 0,
			trovato = 0,
			limite = -1,
			index = 0,
			counter = occurrences,
			ind_temp,
			str_temp,
			string_tab;


	char 	*str_tab,
	*corrente;


	Elf64_Sym *sym64_tab;
	Elf32_Sym *sym32_tab;

	Elf32_Addr addr32;	
	Elf64_Addr addr64;



	// 1) Cerco il nome del simbolo nelle STRTAB, per trovarne l'index corrispondente
	for(i = 0; i < ELF(secnum); i++) {

		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_STRTAB) {

				limite = (int)ELF(sec_hdr)[i]->section64.sh_size;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_STRTAB)
				limite = (int)ELF(sec_hdr)[i]->section32.sh_size;
		}



		if (limite == -1)
			continue;

		str_tab = (char *)ELF(sections)[i] - 1;
		corrente = str_tab;

		while (totale < limite) {

			if (strstr(corrente, name) != NULL) { // Se trovo il simbolo...

				counter--;

				if (counter == 0){

					index = totale; // Salvo l'indice del simbolo
					string_tab = i; // Salvo il numero di sezione della tabella delle stringhe
					trovato = 1;
					break;
				}

			}

			if (strlen(corrente) == 0)
				totale += 1;
			else
				totale += strlen(corrente);

			corrente = str_tab + totale + 1;

		}

		if (trovato == 1) break;

		limite = -1;
		totale= 0;
	}

	if (trovato == 0) {

		printf("Find_symbol: Simbolo non trovato\n");
		return -1;
	}

	printf("Simbolo %s trovato nella sezione %d all'indice %d\n", name, string_tab, index);

	limite = -1;
	totale = 0;
	trovato = 0;

	// 2) Cerco il simbolo nella Sym_Tab per prelevarne il valore
	for(i = 0; i < ELF(secnum); i++) {

		if(ELF(is64)) {
			if(ELF(sec_hdr)[i]->section64.sh_type == SHT_SYMTAB) {

				limite = (int)ELF(sec_hdr)[i]->section64.sh_size;
			}
		} else {
			if(ELF(sec_hdr)[i]->section32.sh_type == SHT_SYMTAB)
				limite = (int)ELF(sec_hdr)[i]->section32.sh_size;
		}

		if (limite == -1)
			continue;

		if(ELF(is64)) {

			sym64_tab = (Elf64_Sym *)(ELF(sections)[i]);
			ind_temp = sym64_tab->st_name;
			str_temp = ELF(sec_hdr)[i]->section64.sh_link;

		} else {

			sym32_tab = (Elf32_Sym *)(ELF(sections)[i]);
			ind_temp = sym32_tab->st_name;
			str_temp = ELF(sec_hdr)[i]->section32.sh_link;
		}


		while (totale < limite) {
			// Confronto st_name del simbolo corrente con quello del simbolo cercato
			if (str_temp == string_tab && ind_temp == index){ 	// Se lo trovo ne salvo st_value

				trovato = 1;

				if(ELF(is64))
					addr64 = sym64_tab->st_value;
				else
					addr32 = sym32_tab->st_value;

				break;
			}

			else{

				if(ELF(is64)) {

					totale = totale + sizeof(Elf64_Sym);
					sym64_tab = (Elf64_Sym *) (ELF(sections)[i] + totale);
					ind_temp = sym64_tab->st_name;

				} else {

					totale = totale + sizeof(Elf32_Sym);
					sym32_tab = (Elf32_Sym *) (ELF(sections)[i] + totale);
					ind_temp = sym32_tab->st_name;

				}
			}

		}

		if (trovato == 1) break;

		totale = 0;
		limite = -1;

	}

	if (trovato == 0) {

		printf("Find_symbol: Valore non trovato\n");
		return -1;

	}



	if(ELF(is64)) {

		printf("Il simbolo %s ha offset = %02lx\n", name, (unsigned long)addr64);
		return addr64;

	} else {

		printf("Il simbolo %s ha offset = %02lx\n", name, (unsigned long)addr32);
		return addr32;
	}

}

#endif /* if 0 */




/*******************************************************************/

static section *relocs;			/// List of all relocations sections parsed
static section *symbols;		/// List of all symbols parsed
static section *code;			/// List of whole code sections parsed
static function *functions;		/// List of resolved functions
static section *data;			/// List of all raw data sections
static char *strings;			/// Array of strings

// FIXME: redundancy with 'add_section'
/**
 * Create and link a new section descriptor.
 * Create a new section descriptor and add it into the list pointed to by the
 * 'first' argument passed.
 *
 * @param type An integer constant which represents the type of the section
 *
 * @param secndx Integer representing the index number of the section in the ELF file
 *
 * @param first Pointer to a list of sections to which append the new one
 */
static void add_sec(int type, int secndx, void *payload, section **first) {
	section *s;

	// Create and populate the new node
	section *new = (section *)malloc(sizeof(section));
	if(!new){
		herror(true, "Out of memory!\n");
	}
	bzero(new, sizeof(section));

	new->type = type;
	new->index = secndx;
	new->header = sec_header(secndx);
	new->payload = payload;

	if(*first == NULL)
		*first = new;
	else {
		s = *first;
		while(s->next != NULL) {
			s = s->next;
		}
		s->next = new;
	}
}

// FIXME: is this really used?
static char *strtab(unsigned int byte) {

	// This will give immediate access to the symbol table's string table,
	// and will be populated upon the first execution of this function.
	static unsigned int sym_strtab = -1;

	int i;

	if(sym_strtab == -1) { // First invocation: must lookup the table!
		for(i = 0; i < ELF(secnum); i++) {
			if(sec_type(i) == SHT_STRTAB && shstrtab_idx() != i) {
				sym_strtab = i;
				break;
			}
		}
	}

	// I assume that if this function was called, at least one symbol
	// is present, so at least one name is, and therefore at least one
	// string table is present, so I don't check if the table does
	// not exist!


	// Now get displace in the section and return
	return (char *)(sec_content(sym_strtab) + byte);

}


static void elf_raw_section(int sec) {

	hnotice(2, "Nothing to do here...\n");

	// We do not need to perform any particular task here...
	add_section(SECTION_RAW, sec, sec_content(sec));

	hdump(3, sec_name(sec), sec_content(sec), sec_size(sec));

	hsuccess();

}






static void elf_code_section(int sec) {
	insn_info 	*first,
	*curr;

	unsigned long 	pos = 0,
			size;

	char flags = 0;

	first = curr = (insn_info *)malloc(sizeof(insn_info));
	bzero(first, sizeof(insn_info));
	size = sec_size(sec);

	// Preset some runtime parameters for instruction set decoding (when needed)
	switch(PROGRAM(insn_set)) {
	case X86_INSN:
		if(ELF(is64)) {
			flags |= DATA_64;
			flags |= ADDR_64;
		} else {
			flags |= DATA_32;
			flags |= ADDR_32;
		}
		break;
	}



	// Decode instructions and build functions map
	while(pos < size) {

		switch(PROGRAM(insn_set)) {

			case X86_INSN:
				x86_disassemble_instruction(sec_content(sec), &pos, &curr->i.x86, flags);
				hnotice(2, "%#08lx: %s (%d)\n", curr->i.x86.initial, curr->i.x86.mnemonic, curr->i.x86.opcode_size);

				// Make flags arch-independent
				curr->flags = curr->i.x86.flags;
				curr->new_addr = curr->orig_addr = curr->i.x86.initial;
				curr->size = curr->i.x86.insn_size;
				curr->opcode_size = curr->i.x86.opcode_size;


				//TODO: debug
				/*hprint("ISTRUZIONE:: '%s' -> opcode = %hhx%hhx, opsize = %d, insn_size = %d; breg = %x, "
						"ireg = %x; disp_offset = %lx, jump_dest = %lx, scale = %lx, span = %lx\n",
						curr->i.x86.mnemonic, curr->i.x86.opcode[1], curr->i.x86.opcode[0], curr->i.x86.opcode_size, curr->i.x86.insn_size,
						curr->i.x86.breg, curr->i.x86.ireg, curr->i.x86.disp_offset, curr->i.x86.jump_dest,
						curr->i.x86.scale, curr->i.x86.span);*/

				break;

			default:
				hinternal();
		}

		// Link the node and continue
		curr->next = (insn_info *)malloc(sizeof(insn_info));
		bzero(curr->next, sizeof(insn_info));
		curr->next->prev = curr;	// Davide
		curr = curr->next;

	}

	// TODO: we left a blank node at the end of the chain!
	//curr->prev->next = 0;
	//free(curr);

	// At this time, we consider the sections just as a sequence of instructions.
	// Later, a second pass on this sequence will divide instructions in functions,
	// but we must be sure to have symbols loaded, which we cannot be at this
	// stage of processing
	// FIXME: eliminare la ridondanza sulle chiamate add_section add_sec!
	add_section(SECTION_CODE, sec, first);
	add_sec(SECTION_CODE, sec, first, &code);

	hsuccess();
}




static void elf_symbol_section(int sec) {

	Elf_Sym *s;
	symbol	*sym, *first, *last;

	unsigned int 	pos = 0;
	unsigned int	size = sec_size(sec);
	unsigned int	sym_count = 0;

	int type;
	int bind;

	first = sym = (symbol *) malloc(sizeof(symbol));
	bzero(first, sizeof(symbol));

	while(pos < size) {

		s = (Elf_Sym *)(sec_content(sec) + pos);
		type = ( ELF(is64) ? ELF64_ST_TYPE(symbol_info(s, st_info)) : ELF32_ST_TYPE(symbol_info(s, st_info)) );
		bind = ( ELF(is64) ? ELF64_ST_BIND(symbol_info(s, st_info)) : ELF32_ST_BIND(symbol_info(s, st_info)) );

		// TODO: handle binding, visibility (for ld.so)

		if(type == STT_OBJECT || type == STT_COMMON || type == STT_FUNC || type == STT_NOTYPE ||
				type == STT_SECTION || type == STT_FILE) {

			switch(type) {
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

			default:
				hinternal();
			}

			sym->name = strtab(symbol_info(s, st_name));
			sym->size = symbol_info(s, st_size);
			sym->extra_flags = symbol_info(s, st_info);
			sym->secnum = symbol_info(s, st_shndx);
			sym->index = sym_count;

			// XXX: "initial" was intended here as the initial value, but st_value refers to the position of the instruction.
			// This was breaking the generation of references in case of local calls.
			// I don't know if it is safe to remove the "initial" field anyhow
			sym->position = symbol_info(s, st_value);
			sym->initial = symbol_info(s, st_value);
			sym->bind = bind;

			hnotice(2, "[%d] %s: '%s' in section %d :: %ld\n", sym->index, (sym->type == SYMBOL_FUNCTION ? "Function" :
					(sym->type == SYMBOL_UNDEF ? "Undefined" :
						sym->type == SYMBOL_SECTION ? "Section" :
							sym->type == SYMBOL_FILE ? "File" :
								"Variable")), sym->name, sym->secnum, sym->position);

			// insert symbol
			sym->next = (symbol *) malloc(sizeof(symbol));
			bzero(sym->next, sizeof(symbol));
			last = sym;
			sym = sym->next;

		}

		sym_count++;
		pos += (ELF(is64) ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym));
	}

	// free the last empty symbol
	last->next = NULL;
	free(sym);

	// TODO: is needed, now, to add symbol chain to the program structure (ie. executable_info)?


	// At this stage symbol section will contain a list of symbols.
	// This section will be appended to the linked list of all section
	// maintained by the program descriptor.
	add_section(SECTION_SYMBOLS, sec, first);
	add_sec(SECTION_SYMBOLS, sec, first, &symbols);

	hsuccess();
}




//TODO: complete relocation by retrieving instruction embedded addend!!
static void elf_rel_section(int sec) {
	Elf_Rel *r;
	reloc *first;
	reloc *rel;

	unsigned int pos = 0;
	unsigned int size = sec_size(sec);
	long long info;

	first = rel = (reloc *) malloc(sizeof(reloc));
	bzero(first, sizeof(reloc));

	while(pos < size){

		r = (Elf_Rel *) (sec_content(sec) + pos);
		info = reloc_info(r, r_info);

		rel->type = ELF(is64) ? ELF64_R_TYPE(info) : ELF32_R_TYPE(info);
		rel->offset = reloc_info(r, r_offset);		// offset from begin of file to which apply the relocation
		rel->s_index = ELF(is64) ? ELF64_R_SYM(info) : ELF32_R_SYM(info);	// section to which reloc symbol refers to
		// the 'addend' paramenters in rel section are embedded in the instruction itself
		// so it is required to retrieve this in a second pass

		// TODO: link symbol to relocation entry, however they are not available yet

		// TODO: Needed to manage properly rel->type field?
		hnotice(2, "%d: Relocation at offset %d of section %#08lx\n", rel->type,
				rel->offset, rel->s_index);

		rel->next = (reloc *) malloc(sizeof(reloc));
		bzero(rel->next, sizeof(reloc));
		rel = rel->next;

		pos += (ELF(is64) ? sizeof(Elf64_Rel) : sizeof(Elf32_Rel));
	}

	// adds the section to the program
	add_section(SECTION_RELOC, sec, first);
	add_sec(SECTION_RELOC, sec, first, &relocs);

	hsuccess();
}



static void elf_rela_section(int sec) {
	Elf_Rela *r;
	reloc *first;
	reloc *rel;

	unsigned int pos = 0;
	unsigned int size = sec_size(sec);
	long long info;

	first = rel = (reloc *) malloc(sizeof(reloc));
	bzero(first, sizeof(reloc));

	while(pos < size){

		r = (Elf_Rela *) (sec_content(sec) + pos);
		info = reloc_info(r, r_info);

		rel->type = ELF(is64) ? ELF64_R_TYPE(info) : ELF32_R_TYPE(info);
		rel->offset = reloc_info(r, r_offset);		// offset within the section to which apply the relocation
		rel->s_index = ELF(is64) ? ELF64_R_SYM(info) : ELF32_R_SYM(info);	// index of symbol relocation refers to
		rel->addend = reloc_info(r, r_addend);		// explicit displacement to add to the offset

		// link symbol to relocation entry, however they are not available yet
		// so it is needed to be done in a future pass

		hnotice(2, "Relocation of type %d refers symbol %d at offset %#08lx\n", rel->type,
				rel->s_index, rel->offset);

		// creates a new node and jumps to next rela entry
		rel->next = (reloc *) malloc(sizeof(reloc));
		bzero(rel->next, sizeof(reloc));
		rel = rel->next;

		pos += (ELF(is64) ? sizeof(Elf64_Rela) : sizeof(Elf32_Rela));
	}

	// adds the section to the program
	add_section(SECTION_RELOC, sec, first);
	add_sec(SECTION_RELOC, sec, first, &relocs);

	hsuccess();
}


static void elf_string_section(int sec) {
	unsigned int pos = 0;
	unsigned int size = sec_size(sec);

	char *name;
	char *strtab = (char *)malloc(sizeof(char) * size);

	while(pos < size){

		name = (sec_content(sec) + pos);
		strcpy(strtab + pos, name);
		hnotice(2, "%#08lx: '%s'\n", pos, strtab+pos);

		pos += (strlen(name) + 1);
	}

	// adds the section to the program
	add_section(SECTION_NAMES, sec, strtab);	//TODO: is this needed?
	//add_sec(SECTION_NAMES, sec, strtab, &strings);
	strings = strtab;

	hsuccess();
}


/**
 * Creates a function descriptor by resolving symbol pointer to code section.
 * In this second pass the parser resolves instruction addresses into function objects dividing them
 * into the right instruction chain belonging to the symbol requested.
 *
 * @param sym Pointer to a 'symbol' descriptor, which represent the current symbol to be resolved into function.
 *
 * @param func Pointer to the 'function' descriptor to be filled. Must be previoulsy allocated.
 *
 */
static void split_function(symbol *sym, function *func) {
	section *sec;
	insn_info *insn, *first;
	int ret_address;

	// check if the type is really a function
	if(sym->type != SYMBOL_FUNCTION){
		hinternal();
	}

	bzero(func, sizeof(function));

	// surf the section list until the one whose index is 'secnum' is found
	sec = code;
	while(sec){
		if(sec->index == sym->secnum)
			break;
		sec = sec->next;
	}
	if(!sec)
		hinternal();

	// check if the section pointed to is actually a code text section
	if(sec->type != SECTION_CODE){
		hinternal();
	}

	// reaches the instruction pointed to by the symbol value
	first = insn = sec->payload;
	while(insn != NULL){
		if(insn->orig_addr == sym->position)
			break;
		insn = insn->next;
	}
	if(!insn)
		hinternal();

	first = insn;
	func->name = sym->name;
	func->insn = insn;
	func->orig_addr = sym->position;
	func->new_addr = func->orig_addr;

	// now, it is necessary to find the end of the function.
	// it's not possible to do it by finding the RET instruction, cause it can be used
	// in the middle of a function for optimization purpose, so we use the 'first' instruction
	// of the current function to brake the chain in reverse, but will be done in a future pass.
}


/**
 * Links jumps instructions to destination ones.
 * Provided a valid function's descriptors, it will look up for all the jump instructions
 * and will link them to their relative destination ones.
 *
 * @param func A pointer to a valid function's descriptors
 */
void link_jump_instruction(function *func) {
	insn_info *insn;	// Current instruction
	insn_info *dest;	// Destination one
	function *callee;	// Callee function
	symbol *sym;		// Callee function's symbol
	long long jmp_addr;	// Jump address

	hnotice(1, "Link jump and call instructions of all functions:\n");

	// For each instruction, look for jump ones
	insn = func->insn;
	while(insn) {
		
		if(IS_JUMP(insn)) {

			// Provided a jump instruction, look for the destination address
			switch(PROGRAM(insn_set)) {
			case X86_INSN:
				jmp_addr = insn->orig_addr + insn->i.x86.insn_size + insn->i.x86.jump_dest;
				break;

			default:
				jmp_addr = -1;
			}

			dest = func->insn;
			while(dest) {
				if(dest->orig_addr == jmp_addr)
					break;

				dest = dest->next;
			}

			if(!dest) {
				hinternal();
			}

			// At this point 'dest' will point to the destination instruction relative to the jump 'insn'
			insn->jumpto = dest;

			hnotice(2, "Jump instruction at <%#08lx> linked to instruction at <%#08lx>\n",
					insn->orig_addr, dest->orig_addr);


		// a CALL could be seen as a JUMP and could help in handling the embedded offset to local functions
		} else if(IS_CALL(insn)) {
			// must create the reference only if the 4-bytes offset is not null
			// Provided a jump instruction, look for the destination address
			switch(PROGRAM(insn_set)) {
			case X86_INSN:
				jmp_addr = insn->i.x86.jump_dest;
				break;

			default:
				jmp_addr = 0;
			}

			if(jmp_addr != 0) {
				
				// Call to local function detected. The format is the same as a jump
				// XXX: credo che fosse scorretto nel caso delle funzioni locali, infatti non trovava la funzione
				//~ jmp_addr += insn->orig_addr + insn->size;
				jmp_addr = insn->orig_addr + insn->i.x86.insn_size + insn->i.x86.jump_dest;
				
				// look for the relative function called
				callee = functions;
				while(callee) {
					
					printf("%#08x, ", callee->orig_addr);
					
					if(callee->orig_addr == jmp_addr)
						break;

					callee = callee->next;
				}

				// mhhh, something goes wrong i guess...
				if(!callee) {
					hinternal();
				}

				// At this point 'func' will point to the destination function relative to the call
				// the only thing we have to do is to add the reference to the relative function's symbol
				// so that, in the future emit step, the code will automatically retrieve the correct final
				// address of the relocation. In such a way we threat local function calls as relocation enties.
				sym = callee->symbol;

				// The instruction object will be bound to the proper symbol
				instruction_rela_node(sym, insn, RELOCATE_RELATIVE_32);

				// CALL instruction embedded offset must be reinitialize to zero
				switch(PROGRAM(insn_set)) {
				case X86_INSN:
					memset(insn->i.x86.insn+1, 0, (insn->size - insn->opcode_size));
					break;
				}

				hnotice(2, "Call instruction at <%#08lx> linked to address <%#08lx>\n",
					insn->orig_addr, callee->orig_addr);
			}
		}

		insn = insn->next;
	}

}

/**
 * Looks for the section with the index specified.
 *
 * @return Returns the pointer to the section found, if any, NULL otherwise.
 */
static inline section * find_section(int index) {
	section *sec = 0;

	sec = PROGRAM(sections);
	while(sec) {
		if(sec->index == index)
			break;
		sec = sec->next;
	}

	return sec;
}


/**
 * Second phase parser which resolves symbols.
 * Resolves symbols by retrieving its type and calling the relative function which handle them correctly.
 * At the end of the phase, instructions within the code section are translated into function objects
 * and returned into the global variable 'functions', whereas variables' values are stored into a data array.
 */
static void resolve_symbols() {
	// This is the second pass needed to divide the instruction chain into function objects.
	// Symbols will resolved and linked to the relative function descriptor object.

	symbol *sym;			// Current symbol to be resolved
	section *sec;			// Current section to be parsed
	insn_info *insn;		// Instruction chain
	function *head, *func;	// Function pointers

	sym = symbols->payload;

	head = func = (function *)malloc(sizeof(function));
	bzero(head, sizeof(function));

	hnotice(1, "Resolving symbols...\n");

	// For each symbol registered, resolve it
	while(sym) {

		switch(sym->type){
		case SYMBOL_FUNCTION:
			func->next = (function *) malloc(sizeof(function));
			func = func->next;

			split_function(sym, func);
			func->symbol = sym;

			hnotice(2, "Function '%s' (%d bytes long) :: <%#08lx>\n", sym->name, sym->size, func->orig_addr);
			break;

		case SYMBOL_VARIABLE:
			if (sym->secnum != SHN_COMMON) {
				sym->position = *(sec_content(sym->secnum) + sym->position);
			}

			hnotice(2, "Variable '%s' (%d bytes long) :: %ld (%s)\n", sym->name, sym->size,
					(sym->secnum != SHN_COMMON) ? *(sec_content(sym->secnum) + sym->position) : sym->position,
							sym->secnum == SHN_COMMON ? "COM" : sec_name(sym->secnum));
			break;

		case SYMBOL_UNDEF:
			hnotice(2, "Undefined symbol '%s' (%d bytes long)\n", sym->name, sym->size);
			break;

		case SYMBOL_SECTION:
			hnotice(2, "Section symbol pointing to section %d (%s)\n", sym->secnum, sec_name(sym->secnum));
			sym->name = sec_name(sym->secnum);
			break;

		case SYMBOL_FILE:
			hnotice(2, "Filename's symbol\n");
			break;

		default:
			hnotice(2, "Unknown type for symbol '%s', skipped\n", sym->name);
		}

		sym = sym->next;
	}

	// save function list
	functions = head->next;
	free(head);

	// Link JUMP instructions and break the instruction chain
	func = functions;

	// links the jump instructions
	link_jump_instruction(func);

	while(func) {
		// breaks the instructions chain
		if(func->insn->prev) {
			func->insn->prev->next = NULL;
		}
		func->insn->prev = NULL;

		func = func->next;
	}

	hsuccess();
}


/**
 * Third phase which resolves relocation.
 * Resolves each relocation entry stored in previous phase, by looking for each symbol name and binding them
 * to the relative reference. In particular, in functions each instruction descriptor handles a 'reference'
 * void * pointer which can represent either a variable or a call instruction to a specific address.
 * In case of a reference to an 'undefined' symbol, which probably means an external library function, a
 * temporary NULL pointer is set.
 *
 * If the symbol or the code address referenced to by the relocation entry was not found a warning is issued,
 * but the parsing goes on.
 */
static void resolve_relocation(){
	reloc *rel;
	function *func, *prev;
	insn_info *insn;
	symbol *sym, *sym_2;
	section *sec, *tarsec;
	int target, flags;

	hnotice(1, "Resolving relocation entries...\n");

	// Part of this work it already done in the previous step performed by 'link_jump_instruction' function

	// Get the list of parsed relocation sections
	sec = relocs;

	// For each relocation section
	while(sec) {

		hnotice(2, "Parsing next relocation section\n\n");

		// Retrieve relocation's metadata
		target = sec_field(sec->index, sh_info);
		flags = sec_field(target, sh_flags);


		// Retrieve the payload and cycles on each relocation entry
		rel = sec->payload;
		while(rel) {

			// We look for the symbol pointed to by the relocation's 'info' field
			hnotice(2, "Looking up for symbol reference at index %d\n", rel->s_index);

			sym = symbols->payload;
			while(sym) {
				if(sym->index == rel->s_index && rel->s_index){
					hnotice(3, "Symbol found: '%s' [%s]\n", sym->name,
							sym->type == SYMBOL_FUNCTION ? "function" :
									sym->type == SYMBOL_VARIABLE ? "variable" :
											sym->type == SYMBOL_SECTION ? "section" : "undefined");
					break;
				}
				sym = sym->next;
			}

			// Symbol does not exists, can we assume it was not important?
			// continue parsing the next relocation entry
			if(!sym){
				hnotice(3, "Symbol not found!\n\n");
				rel = rel->next;
				continue;
			}

			rel->symbol = sym;

			if(flags & SHF_EXECINSTR) {
				// the relocation applies to an instruction
				hnotice(3, "Looking up for address <%#08lx>\n", rel->offset);

				// Search in the function list the one containing the right instruction.
				// This is simply done by looking for the function whose starting offset
				// is the closest address to one relocation refers to.
				func = functions;
				insn = NULL;
				while(func->next){
					if(func->next->orig_addr > (unsigned long long)rel->offset){
						break;
					}

					func = func->next;
				}

				if(func) {
					hnotice(3, "Relocation is found to be in function at <%#08lx> (%s)\n", func->orig_addr, func->name);
					insn = func->insn;
				}

				// At this point 'insn' (should) contains the first instruction of the
				// correct function to which apply the relocation.
				// Now we have to look for the right instruction pointed to by the offset.
				// in order to do that is sufficient to look up for the instructions whose
				// address is the closest to the one relocation refers to.
				// Note that '>' is because the relocation actually does not refer to
				// the instruction's address itself, but it is shifted by the opcode size.
				while(insn->next) {
					if(insn->next->orig_addr > (unsigned long long)rel->offset){
						break;
					}

					insn = insn->next;
				}

				// if insn is NULL, uuh...something is going wrong!
				if(insn) {
					hnotice(3, "Instruction pointed to by relocation: <%#08lx> '%s'\n", insn->orig_addr,
							insn->i.x86.mnemonic);


					// TODO: now there is the create_rela_node functions, use it!
					// Check for relocation duplicates
					sym_2 = symbol_check_shared(sym);
					sym_2->referenced = 1;
					sym_2->relocation.addend = rel->addend;
					sym_2->relocation.type = rel->type;
					sym_2->relocation.secname = ".text";
					sym_2->relocation.ref_insn = insn;

					// The instruction object will be bound to the proper symbol.
					// This reference is read by the specific machine code emitter
					// that is in charge to proper handle the relocation.
					insn->reference = sym_2;

					hnotice(2, "Symbol reference added\n\n");

				} else {
					herror(true, "Relocation cannot be applied, reference not found\n\n");
				}
			} else {
				// If the section's flags are not EXEC_INSTR, then this means that
				// the relocation does not apply to an instruction but to another symbol;
				// e.g. a SECTION symbol, in case of generic references (.data, .bss, .rodata)
				
				// If we are here, the relocation is SECTION->SECTION, otherwise
				// an instruction would be found in the previous branch.

				// TODO: now there is the create_rela_node function, so use it!
				// Check for relocation duplicates
				sym_2 = symbol_check_shared(sym);
				sym_2->referenced = 1;
				sym_2->relocation.addend = rel->addend;
				sym_2->relocation.offset = rel->offset;
				sym_2->relocation.type = rel->type;
				sym_2->relocation.secname = sec->name;
				

				hnotice(2, "Added symbol reference to <%#08lx> + %d\n", rel->offset, rel->addend);
			}

			rel = rel->next;
		}

		sec = sec->next;
	}

	hsuccess();
}


void elf_create_map(void) {
	unsigned int size;
	unsigned int sec;
	section **sections;


	// Reserve space and load ELF in memory
	fseek(ELF(pointer), 0L, SEEK_END);
	size = ftell(ELF(pointer));
	rewind(ELF(pointer));
	ELF(data) = malloc(size * sizeof(unsigned char));
	if(fread(ELF(data), 1, size, ELF(pointer)) != size) {
		herror(true, "Unable to correctly load the ELF file\n");
	}
	rewind(ELF(pointer));

	// Keep track of the header
	ELF(hdr) = (Elf_Hdr *)ELF(data);

	// Where is the section header?
	if(ELF(is64))
		ELF(sec_hdr) = (Section_Hdr *)(ELF(data) + ELF(hdr)->header64.e_shoff);
	else
		ELF(sec_hdr) = (Section_Hdr *)(ELF(data) + ELF(hdr)->header32.e_shoff);

	// How many sections are in the ELF?
	if(ELF(is64))
		ELF(secnum) = ELF(hdr)->header64.e_shnum;
	else
		ELF(secnum) = ELF(hdr)->header32.e_shnum;

	hnotice(1, "Found %u sections...\n", ELF(secnum));

	// Scan ELF Sections and convert/parse them (if any to be)
	for(sec = 0; sec < ELF(secnum); sec++) {

		hnotice(1, "Parsing section %d: '%s' (%d bytes long, offset %#08lx)\n",
				sec, sec_name(sec), sec_size(sec), sec_field(sec, sh_offset));

		switch(sec_type(sec)) {

		case SHT_PROGBITS:
			if(sec_test_flag(sec, SHF_EXECINSTR)) {
				elf_code_section(sec);
			} else {
				elf_raw_section(sec); // Qui è sicuramente una sezione data
			}
			break;

		case SHT_SYMTAB:
			elf_symbol_section(sec);
			break;

		case SHT_NOBITS:
			elf_raw_section(sec);
			break;

		case SHT_REL:
			elf_rel_section(sec);
			break;

		case SHT_RELA:
			if(!strcmp(sec_name(sec), ".rela.text"))
				elf_rela_section(sec);
			else if(!strcmp(sec_name(sec), ".rela.data"))
				elf_rela_section(sec);
			else if(!strcmp(sec_name(sec), ".rela.rodata"))
				elf_rela_section(sec);
			else if(!strcmp(sec_name(sec), ".rela.bss"))
				elf_rela_section(sec);
			break;

		case SHT_STRTAB:
			elf_string_section(sec);
			break;

		case SHT_HASH:
		case SHT_DYNAMIC:
		case SHT_DYNSYM:
			elf_raw_section(sec);
			break;
		}
	}

	resolve_symbols();
	resolve_relocation();

	PROGRAM(symbols) = symbols->payload;
	PROGRAM(code) = PROGRAM(v_code)[0] = functions;
	PROGRAM(rawdata) = 0;
	PROGRAM(versions)++;

	hnotice(1, "ELF parsing terminated\n\n");
	hsuccess();
}








int elf_instruction_set(void) {
	Elf32_Ehdr hdr; // Headers are same sized. Assuming its 32 bits...
	int insn_set = UNRECOG_INSN;

	hnotice(1, "Determining instruction set... ");

	// Load ELF Header
	if(fread(&hdr, 1, sizeof(Elf32_Ehdr), ELF(pointer)) != sizeof(Elf32_Ehdr)) {
		herror(true, "An error occurred while reading program header\n");
	}

	// Switch on proper field
	switch(hdr.e_machine) {

		case EM_386:
		case EM_X86_64:
			insn_set = X86_INSN;
			break;
		}


	if(insn_set == UNRECOG_INSN) {
		hfail();
	} else {
		hsuccess();
	}

	rewind(ELF(pointer));

	return insn_set;
}




bool is_elf(char *path) {
	Elf32_Ehdr hdr; // Headers are same sized. Assuming its 32 bits...

	hnotice(1, "Checking whether '%s' is an ELF executable...", path);

	// Try to oper the file
	ELF(pointer) = fopen(path, "r+");
	if(ELF(pointer) == NULL) {
		herror(true, "Unable to open '%s' for reading\n", path);
	}


	// Load ELF Header
	if(fread(&hdr, 1, sizeof(Elf32_Ehdr), ELF(pointer)) != sizeof(Elf32_Ehdr)) {
		herror(true, "An error occurred while reading program header\n");
	}

	// Is it a valid ELF?!
	if(hdr.e_ident[EI_MAG0] != ELFMAG0 ||
			hdr.e_ident[EI_MAG1] != ELFMAG1 ||
			hdr.e_ident[EI_MAG2] != ELFMAG2 ||
			hdr.e_ident[EI_MAG3] != ELFMAG3) {
		fclose(ELF(pointer));
		hfail();
		return false;
	}

	// We cannot deal with executables, only with relocatable objects
	if(hdr.e_type != ET_REL) {
		herror(true, "Can analyze only relocatable ELF objects\n");
	}

	// Is the current ELF 32- or 64-bits?
	switch(hdr.e_ident[EI_CLASS]) {
	case ELFCLASS32:
		ELF(is64) = false;
		break;
	case ELFCLASS64:
		ELF(is64) = true;
		break;
	default:
		herror(true, "Invalid ELF class\n");
	}

	// Reset the file descriptor
	rewind(ELF(pointer));

	hsuccess();
	return true;
}

