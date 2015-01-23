// Test executable. On x86 it will produce code testing most of hijacker capabilities

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int variable;
char var;
int target = 10;


int greater(int a, int b) {
	if(a > b)
		return 1;
	else
		return 0;
}

int bar(int n) {
	variable++;
	variable *= n;
	return variable;
}


void foo(void) {
	printf("Iteration %d\n", var++);
	printf("variable is greater than target(%d)? %s\n", target, greater(variable, target) ? "YES" : "NO");
}

int main(int argc char *argv[]) {
	static int counter = 0;
	char *addr;

	addr = malloc(sizeof(char));
	*addr = bar(2);
	
	printf("Addr contains to %d\n", *addr);

	while(var < 20) {
		foo();
		bar(3);
		printf("Var = %d\n", var++);
	}

	return 0;
}
