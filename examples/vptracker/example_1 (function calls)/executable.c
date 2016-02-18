// Test executable. On x86 it will produce code testing most of hijacker capabilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int variabile;
char var;

/* WORKS */
/* int foo(int a, int b) {
	int c;

	c = b + 2*a;
	variabile += c;

	return 0;
} */

/* DOESN'T WORK */
int greater(int a, int b) {
	if(a > b)
		return 1;
	else
		return 0;
}

int main(void) {
	void *addr = malloc(1);
	printf("%p\n", addr);
	return 0;
}

