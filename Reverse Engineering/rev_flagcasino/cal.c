#include <stdio.h>
#include <stdlib.h>

unsigned int values[] = {

};

int main() {
    unsigned int check[] = {0};
    int i = 0;

    for (int c = 0; c <= 2147483647; c++) {
        srand(c);
        if (rand() == check[i]) {
            printf("Char for index %d: %c (0x%02x)\n", i, c, c);
            break;
        }
    }
    return 0;
}
