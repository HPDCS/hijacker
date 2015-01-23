/* Il monitor è una funzione che viene invocata senza alcun passaggio di
 * argomenti. Questo può avvenire perché, dopo essere stato compilato, il
 * parser popola automaticamente la tabella delle istruzioni con tutte le
 * informazioni necessarie.
 * In questo modo, l'unica cosa che deve fare il monitor è recuperare l'indirizzo
 * di ritorno nello stack ed andarlo a cercare nella tabella stessa.
 * È evidente che la tabella *deve* essere popolata prima dell'esecuzione. Se non viene
 * specificata DIM, si suppone che la compilazione non sia stata chiamata dal
 * parser e quindi viene generato un errore che interrompa la compilazione
 */
#ifndef DIM
 #error "Errore: dimensione della tabella di istruzioni instrumentate non definita"
#endif

#ifndef IA32
 #ifndef IA64
  #error "Errore: occorre specificare se si sta compilando per 32 o 64 bit"
 #endif
#endif


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "monitor.h"


int monitor_disabled __attribute__ ((section (".monitor_var")));

/* Questa tabella contiene tutte le informazioni relative alle istruzioni che sono
 * state instrumentate nel software di livello applicativo.
 * Viene creata in un'altra sezione in modo tale che possa essere facilmente individuata
 * all'interno dell'ELF per essere popolata.
 */
insn_entry insn_table[DIM] __attribute__ ((section (".insn_table")));

void enable_monitor() {
	monitor_disabled = 0;
}

void disable_monitor() {
	monitor_disabled = 1;
}
