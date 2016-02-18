#include <stdio.h>

void myfunc(unsigned long addr, unsigned long size) {
  unsigned long *buffer = (unsigned long *) addr;
  int i;

  printf("\nDump address at <%#08llx> of %lu entries\n\n", addr, size);

  for (i = 0; i < size * 2; i = i+2) {
    printf("\tFound vpage <%#016llx> accessed %u times\n", buffer[i], buffer[i+1]);
  }
}
