#include <stdio.h>
#include <stdlib.h>

#define PACKAGE 1
#define PACKAGE_VERSION 1

#include <bfd.h>

void hexdump (void *addr, int len) {
  int i;
  int count;
  unsigned char buff[17];
  unsigned char *pc = (unsigned char*)addr;

  if (len <= 0) {
    return;
  }

  printf ("       Address                     Hexadecimal values                      Printable     \n" );
  printf ("   ----------------  ------------------------------------------------  ------------------\n" );

  // Process every byte in the data.
  if (len % 16 != 0 && len > 16)
    count = ((len / 16) + 1) * 16;
  else
    count = len;

  for (i = 0; i < count; i++) {

    // Multiple of 8 means mid-line (add a mid-space)
    if ((i % 8) == 0) {
      if (i != 0)
        printf(" ");
    }

    if (i < len) {
      // Multiple of 16 means new line (with line offset).
      if ((i % 16) == 0) {
        // Just don't print ASCII for the zeroth line.
        if (i != 0)
          printf (" |%s|\n", buff);

        // Output the offset.
        printf ("   (%5d) %08x ", i, i);
      }

      // Now the hex code for the specific character.
      printf (" %02x", pc[i]);

      // And store a printable ASCII character for later.
      if ((pc[i] < 0x20) || (pc[i] > 0x7e))
        buff[i % 16] = '.';
      else
        buff[i % 16] = pc[i];
      buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    else {

      // Add a three-char long space for the missing character in the second column.
      printf("   ");

      // Add a printable dot for the missing character in the third column.
      buff[i % 16] = '.';
      buff[(i % 16) + 1] = '\0';
    }
  }

  // And print the final ASCII bit.
  printf ("  |%s|\n", buff);
}


int main(size_t argc, char **argv) {
  if (argc != 2) {
    exit(-1);
  }

  bfd *abfd;
  bfd_error_type err;
  const char *errmsg;

  bfd_init();

  abfd = bfd_openr(argv[1], NULL);

  if (abfd == NULL) {
    err = bfd_get_error();
    errmsg = bfd_errmsg(err);

    bfd_perror(errmsg);
  }

  printf("Format `%s`\n",
    bfd_check_format(abfd, bfd_object) ? bfd_format_string(bfd_object) :
    bfd_check_format(abfd, bfd_archive) ? bfd_format_string(bfd_archive) :
    bfd_check_format(abfd, bfd_core) ? bfd_format_string(bfd_core) :
    "Unrecognised"
  );

  printf("Architecture `%s`\n", bfd_printable_name(abfd));

  printf("\n");
  printf("SECTIONS:                                    \n");
  printf("---------------------------------------------\n");

  asection *sec;
  void *payload;

  for (sec = abfd->sections; sec != NULL; sec = sec->next) {
    printf("Section `%s` of size %d bytes\n",
      sec->name, sec->size);

    payload = malloc(sec->size);
    if (payload == NULL) {
      exit(-1);
    }

    bfd_get_section_contents(abfd, sec, payload, 0, sec->size);

    printf("\n");
    hexdump(payload, sec->size);
    printf("\n");
  }

  printf("\n");
  printf("SYMBOLS:                                     \n");
  printf("---------------------------------------------\n");

  asymbol **symbol_table, *sym;
  long nsym, i;

  symbol_table = calloc(bfd_get_symtab_upper_bound(abfd), 1);
  if (symbol_table == NULL) {
    exit(-1);
  }

  // Materializes the symbol table in memory
  nsym = bfd_canonicalize_symtab(abfd, symbol_table);

  for (i = 0; i < nsym; ++i) {
    sym = symbol_table[i];

    printf("Symbol `%s` in section `%s`\n",
      sym->name, sym->section->name);

    printf("\n\t");
    bfd_print_symbol_vandf(abfd, stdout, sym);
    printf("\n\n");
  }

  printf("\n");
  printf("RELOCATIONS:                                 \n");
  printf("---------------------------------------------\n");

  arelent **relocs, *rel;
  long nrel, j;

  for (sec = abfd->sections; sec != NULL; sec = sec->next) {
    relocs = malloc(bfd_get_reloc_upper_bound(abfd, sec));
    if (relocs == NULL) {
      exit(-1);
    }

    // Materializes relocations in memory
    nrel = bfd_canonicalize_reloc(abfd, sec, relocs, symbol_table);

    for (j = 0; j < nrel; ++j) {
      rel = relocs[j];

      printf("Relocation in section `%s` at %p to symbol '%s' +%p\n",
        sec->name, rel->address, (*rel->sym_ptr_ptr)->name, rel->addend);

      printf("\n\t%s\t%s\n\n", rel->howto->name, bfd_get_reloc_code_name(rel->howto->type));
    }
  }

  bfd_close(abfd);

  return 0;
}
