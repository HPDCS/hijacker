// Test executable. On x86 it will produce code testing most of hijacker capabilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int variabile;
static char var;
static short num = 3;

int foo(int a, int b) {
	int c;

	c = b + 2*a;
	variabile += c;

	return 0;
}

void bar(void) {
	static int count = 0;

	printf("Iterazione %d:\n", count++);
	printf("Var = %x\n", var);
}

int foobar(void) {
	num *= variabile;

	return num;
}

int greater(int a, int b) {
	if(a > b)
		return 1;
	else
		return 0;
}

void nop(){}

int main(void) {
	int temp;

	printf("Avvio del programma di test...\n");

	void *addr = malloc(1);

	*((char *) addr) = 5;

	bar();
	var = 10;
	bar();

	variabile = 0;

	while(var) {
		bar();
		foo(var, num);
		var--;

		greater(var, variabile);
	}

	free(addr);

	printf("Programma test terminato.\n");

	return 0;
}
