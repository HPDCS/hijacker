#pragma once
#ifndef _PE_H
#define _PE_H

typedef struct {
	int payload;
} pe_file;

#define PE(field) (config.program.e.pe.field)

extern void pe_create_map(void);
extern int pe_instruction_set(void);
extern bool is_pe(char *path);

#endif /* _PE_H */

