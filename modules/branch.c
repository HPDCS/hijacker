#ifndef OFF_DIM
 #error "Errore: dimensione della tabella degli offset non definita"
#endif

#ifndef BRANCH_DIM
 #error "Errore: dimensione della tabella delle jump instrumentate non definita"
#endif

#include "branch.h"

unsigned int add_counter = 0;
unsigned int sub_counter = 0;

off_table branch_offsets[OFF_DIM] __attribute__ ((section (".offset_table")));
branch_table branch_insns[BRANCH_DIM] __attribute__ ((section (".branch_table")));
