#pragma once

#define IA 16807
#define IM 2147483647
#define AM (1.0/IM)
#define IQ 127773
#define IR 2836
#define MASK 123459876

extern void Srand(long *);
extern float Random(long *);
extern double Expent(long *, double);
