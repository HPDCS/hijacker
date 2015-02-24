#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include "rng.h"


#define CLOCK_READ() ({ \
			unsigned int lo; \
			unsigned int hi; \
			__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi)); \
			((unsigned long long)hi) << 32 | lo; \
			})


void Srand(long *idum) {
	*idum = (long)CLOCK_READ();
}

float Random(long *idum) {
	long k;
	float ans;

	*idum ^= MASK;
	k = (*idum) / IQ;
	*idum = IA * (*idum - k * IQ) - IR * k;
	if (*idum < 0) *idum += IM;
	ans = AM * (*idum);
	*idum ^= MASK;

	return ans;
}


double Expent(long *idum, double mean) {

	if(mean < 0) {
		fprintf(stderr, "Error in call to Expent(): passed a negative mean value\n");
		abort();
	}

	return (-mean * log(1 - Random(idum)));
}
