#ifndef OFF_DIM_LIGHT
 #error "Errore: dimensione della tabella degli offset non definita"
#endif

#ifndef BRANCH_DIM_LIGHT
 #error "Errore: dimensione della tabella delle jump instrumentate non definita"
#endif

#include "branch.h"

unsigned int sub_counter = 0;

off_table branch_offsets_l[OFF_DIM_LIGHT] __attribute__ ((section (".offset_table_l")));
branch_table branch_insns_l[BRANCH_DIM_LIGHT] __attribute__ ((section (".branch_table_l")));
