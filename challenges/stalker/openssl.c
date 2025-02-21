#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUFFER_SIZE 128

// Processes the input string and takes different paths based on its content.
// Returns 1 if a "special" condition is met, or 0 if not.
int process_input(const char *input) {
    char buffer[BUFFER_SIZE];
    size_t len = strlen(input);
    
    // Remove newline if present
    if (len > 0 && input[len - 1] == '\n') {
        len--;
    }
    
    if (len >= sizeof(buffer)) {
        printf("Input too long\n");
        return 0;
    }
    
    // Simple XOR with 0x55 for demonstration (our pseudo 'encryption')
    for (size_t i = 0; i < len; i++) {
        buffer[i] = input[i] ^ 0x55;
    }
    buffer[len] = '\0';
    
    // Multiple execution paths based on the input:
    if (strcmp(input, "admin") == 0) {
        printf("[+] Admin access granted\n");
        return 1;
    } else if (strstr(input, "0x1337") != NULL) {
        printf("[+] Exploit pattern detected\n");
        return 1;
    } else if (buffer[0] == 'X') { // arbitrary condition on the XOR output
        printf("[+] Pattern X found in XOR output\n");
        return 1;
    } else {
        printf("[-] No special pattern detected. XORed output: %s\n", buffer);
        return 0;
    }
}

int main() {
    char input[BUFFER_SIZE];
    
    while (1) {
        printf("Enter input: ");
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("Error reading input. Exiting...\n");
            break;
        }
        
        // Process input; if a special condition is met, exit the loop.
        if (process_input(input)) {
            break;
        }
    }
    
    return 0;
}
