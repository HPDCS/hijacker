#include <stdio.h>
#include <stdlib.h>

int fib(int n) {
  // if (n <= 0)
  //   return 1;
  // else if (n == 1)
  //   return 1;
  if (n <= 1)
    return 1;
  else
    return fib(n-2) + fib(n-1);
}

int foo(void) {
  fib(32);
}
