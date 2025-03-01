#include <stdio.h>
#include <unistd.h>

int main() {
    int count = 0;
    while (1) {
        printf("The count is at: %d\n", count);
        count++;
        sleep(1); // Sleep so it doesn't scroll too fast
    }
    return 0;
}
