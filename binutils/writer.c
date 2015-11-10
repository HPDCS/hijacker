#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

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

  bfd *abfd, *newbfd;
  bfd_error_type err;
  const char *errmsg;

  bfd_init();

  abfd = bfd_openr(argv[1], NULL);
  if (abfd == NULL) {
    err = bfd_get_error();
    errmsg = bfd_errmsg(err);

    bfd_perror(errmsg);
  }

  // To get architectural info, we first need libbfd to check the object format
  if(!bfd_check_format(abfd, bfd_object) &&
     !bfd_check_format(abfd, bfd_archive) &&
     !bfd_check_format(abfd, bfd_core)) {
    bfd_perror("Unknown format read");
  }

  newbfd = bfd_openw("new.o", abfd->xvec->name);
  if (newbfd == NULL) {
    err = bfd_get_error();
    errmsg = bfd_errmsg(err);

    bfd_perror(errmsg);
  }

  bfd_set_format(newbfd, bfd_object);
  bfd_set_arch_info(newbfd, bfd_get_arch_info(abfd));

  // SECTION
  // ---------------------------------------------

  asection *sec = bfd_make_section_with_flags(
    newbfd, ".antani", SEC_DATA | SEC_ALLOC | SEC_HAS_CONTENTS | SEC_RELOC);

  if (sec == NULL) {
    err = bfd_get_error();
    errmsg = bfd_errmsg(err);

    bfd_perror(errmsg);
  }

  sec->size = 1024;

  // SYMBOL
  // ---------------------------------------------

  asymbol *sym = bfd_make_empty_symbol(newbfd);
  sym->name = "come_se_fosse";
  sym->section = sec;
  sym->flags = BSF_GLOBAL;
  sym->value = 0x12345;

  asymbol *symtab[2];
  symtab[0] = sym;
  symtab[1] = NULL;

  bfd_set_symtab(newbfd, symtab, 1);

  // RELOCATION
  // ---------------------------------------------

  arelent *rel = malloc(sizeof(arelent));
  rel->address = 0x55;
  rel->addend = -4;
  rel->sym_ptr_ptr = &sym;
  rel->howto = bfd_reloc_type_lookup(newbfd, BFD_RELOC_32_PCREL);

  arelent *reltab[2];
  reltab[0] = rel;
  reltab[1] = NULL;

  bfd_set_reloc(newbfd, sec, reltab, 1);

  bfd_close(abfd);
  bfd_close(newbfd);

  return 0;
}
