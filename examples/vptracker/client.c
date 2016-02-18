#include <stdlib.h>

extern int foo_monitor(void);
extern int foo(void);

int main(int argc, char **argv) {
  int i, x, y;

  i = 0; x = 0; y = 5;

  for (; i < y; ++i) {
    x += y;
  }

  if (argc >= 2) {
    foo_monitor();
  } else {
    foo();
  }

  ++x;

}
