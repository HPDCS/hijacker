#include <stdio.h>

__thread unsigned int tls_external = 7;

void prova() {
  printf("Prova %lu\n", tls_external);
}
