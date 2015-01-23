// Test executable. On x86 it will produce code testing most of hijacker capabilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int variabile;
char var;

int main(void) {
	void *addr = malloc(1);
	printf("%p\n", addr);
	return 0;
}
