#ifndef _MONITOR_H
#define _MONITOR_H

#ifdef IA32
 #include "monitor32.h"
 typedef insn_entry_32 insn_entry;

 // Dimensione dei dati
 typedef unsigned long size_addr;
#endif


#ifdef IA64
 #include "monitor64.h"
 typedef insn_entry_64 insn_entry;

 // Dimensione dei dati
 typedef unsigned long long size_addr;
#endif

/* Flag inseriti dal parser nella tabella */
#define MOVS		0x01
#define BASE		0x02
#define	IDX		0x04

/* Test sui flag */
#define is_movs(f) 		((f) & MOVS)
#define has_base(f)		((f) & BASE)
#define has_idx(f)		((f) & IDX)

/* Codifiche dei registri.
 * Le codifiche dei registri sono valide per qualsiasi modalità di esecuzione.
 * Se eseguiamo a 64 bit, gli 8 registri general purpose hanno semplicemente
 * i nomi che iniziano per R.
 * Se eseguiamo a 32 bit, i nomi iniziano per E.
 * In modalità 16-bit compatibile, i registri hanno sempre le stesse dimensioni
 * (32 o 64 bit), ma vengono usati i 16 meno significativi.
 *
 * Per generalità, usiamo i nomi dei registri in modalità a 64 bit.
 *
 * Gli unici indirizzi che ci interessa controllare sono quelli general purpose:
 * L'indirizzamento in memoria, infatti, è del tipo:
 * [base] + [index] * scale + displacement
 * e gli unici registri che si possono utilizzare sono quelli general purpose.
 */

//				REX.B	r r r
#define R_AX	0x00	//	  0	0 0 0
#define R_CX	0x01	//	  0	0 0 1
#define R_DX	0x02	//	  0	0 1 0
#define R_BX	0x03	//	  0	0 1 1
#define R_SP	0x04	//	  0	1 0 0
#define R_BP	0x05	//	  0	1 0 1
#define R_SI	0x06	//	  0	1 1 0
#define R_DI	0x07	//	  0	1 1 1
#define R_8	0x08	//	  1	0 0 0
#define R_9	0x09	//	  1	0 0 1
#define R_10	0x0a	//	  1	0 1 0
#define R_11	0x0b	//	  1	0 1 1
#define R_12	0x0c	//	  1	1 0 0
#define R_13	0x0e	//	  1	1 0 1
#define R_14	0x0d	//	  1	1 1 0
#define R_15	0x0f	//	  1	1 1 1

#endif /* _MONITOR_H */
