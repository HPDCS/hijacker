void main() {
  int i, j, k;
  int sum = 0;

  for (i = 0; i < 5; ++i) {
    for (j = 0; j < 9; ++j) {
      for (k = 0; k < 8; ++k) {
        sum += i + j + k;
      }
    }
  }
}
