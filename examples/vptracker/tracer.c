#include <stdio.h>

void writefunc(unsigned long addr, unsigned int size) {
  printf("Detected memory write at <%#08llx> of bytes %u\n", addr, size);
}

void readfunc(unsigned long addr, unsigned int size) {
  printf("Detected memory read at <%#08llx> of bytes %u\n", addr, size);
}
