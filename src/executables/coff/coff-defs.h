#pragma once
#ifndef _COFF_H
#define _COFF_H

typedef struct {
	int payload;
} coff_file;

#define COFF(field) (config.program.e.coff.field)

extern void coff_create_map(void);
extern int coff_instruction_set(void);
extern bool is_coff(char *path);


#endif /* _COFF_H */
