#include <stdio.h>
#include <stdlib.h>

// #define rows_a 5
// #define cols_a 6
// #define cols_b 7

// int matrix_a[rows_a][cols_a];
// int matrix_b[cols_a][cols_b];
// int matrix_c[rows_a][cols_b];

int foo(void) {
  unsigned int rows_a, cols_a, cols_b;

  scanf("%u %u %u", &rows_a, &cols_a, &cols_b);

  // int matrix_a[rows_a][cols_a];
  // int matrix_b[cols_a][cols_b];
  // int matrix_c[rows_a][cols_b];

  int *matrix_a = malloc(rows_a * cols_a * sizeof(int));
  int *matrix_b = malloc(cols_a * cols_b * sizeof(int));
  int *matrix_c = calloc(rows_a * cols_b * sizeof(int), 1);

  unsigned int i, j, k;

  for (i = 0; i < rows_a; ++i) {
    for (j = 0; j < cols_b; ++j) {
      for (k = 0; k < cols_a; ++k) {
        matrix_c[i * cols_a + j] += matrix_a[i * cols_a + k] * matrix_b[k * cols_b + j];
        // matrix_c[i][j] += matrix_a[i][k] * matrix_b[k][j];
      }
    }
  }

  for (i = 0; i < rows_a; ++i) {
    for (j = 0; j < cols_b; ++j) {
      printf("%d ", matrix_c[i * cols_a + j]);
      // printf("%d ", matrix_c[i][j]);
    }
    printf("\n");
  }
}

