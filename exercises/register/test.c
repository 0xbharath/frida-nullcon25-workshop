/**
 * Enterprise License Validator
 *
 * This program validates a license key by computing a hash from the user‐provided
 * key, applying additional obfuscation (XOR and arithmetic operations), and comparing
 * the result to a predefined expected value.
 *
 * The license check logic is designed to be non‐trivial, emulating an enterprise
 * scenario where licensing is enforced via multiple layers of computation.
 *
 * Additionally, this program serves as a target for dynamic instrumentation using
 * tools like Frida to demonstrate runtime register manipulation.
 *
 * Compilation:
 *    gcc -Wall -Wextra -O2 -fno-stack-protector -no-pie -o license_validator license_validator.c
 *
 * Author: [Your Name]
 * Date: [YYYY-MM-DD]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LICENSE_BUFFER_SIZE   128
#define MANIPULATED_EXPECTED  0xDEADBEEF
#define HASH_MULTIPLIER       31
#define OBFUSCATION_XOR       0xCAFEBABE
#define OBFUSCATION_SUBTRACT  0x123456

/**
 * compute_hash - Computes a simple hash from the license key.
 * @input: Pointer to the license key string.
 *
 * This function multiplies the current hash by a constant and adds the
 * numeric value of the current character. This process is repeated for
 * the entire string.
 *
 * Return: Computed hash as an unsigned integer.
 */
unsigned int compute_hash(const char *input) {
    unsigned int hash = 0;
    if (input == NULL) {
        return hash;
    }
    while (*input) {
        hash = (hash * HASH_MULTIPLIER) + (unsigned char)(*input);
        input++;
    }
    return hash;
}

/**
 * verify_manipulated - Verifies that the manipulated value matches the expected constant.
 * @manipulated: The computed value after obfuscation.
 *
 * Return: 1 if the value is valid (i.e. equals MANIPULATED_EXPECTED), 0 otherwise.
 */
int verify_manipulated(unsigned int manipulated) {
    return (manipulated == MANIPULATED_EXPECTED) ? 1 : 0;
}

/**
 * validate_license - Processes and validates the license key.
 * @license: Pointer to the license key string.
 *
 * This function computes the hash from the license, applies obfuscation, and then
 * uses verify_manipulated() to check if the license key is valid. The computed hash
 * and manipulated values are printed to assist with debugging and analysis.
 */
void validate_license(const char *license) {
    if (license == NULL) {
        fprintf(stderr, "Invalid license input.\n");
        return;
    }

    unsigned int hash = compute_hash(license);
    unsigned int manipulated = (hash ^ OBFUSCATION_XOR) - OBFUSCATION_SUBTRACT;
    
    printf("Computed hash:      0x%X\n", hash);
    printf("Manipulated value:  0x%X\n", manipulated);
    
    if (verify_manipulated(manipulated)) {
        printf("License Validated:  Access Granted!\n");
    } else {
        printf("License Validation Failed: Invalid License Key.\n");
    }
}

/**
 * read_license_key - Safely reads a license key from standard input.
 * @buffer: Pointer to the buffer where the license key will be stored.
 * @bufsize: The size of the buffer.
 *
 * This function uses fgets() to safely capture input and removes any trailing newline.
 *
 * Return: 0 on success, -1 on error.
 */
int read_license_key(char *buffer, size_t bufsize) {
    if (buffer == NULL || bufsize == 0) {
        errno = EINVAL;
        return -1;
    }
    
    if (fgets(buffer, bufsize, stdin) == NULL) {
        return -1;
    }
    
    /* Remove any trailing newline character */
    buffer[strcspn(buffer, "\n")] = '\0';
    return 0;
}

/**
 * main - Entry point for the license validator program.
 *
 * Return: EXIT_SUCCESS on success, EXIT_FAILURE on error.
 */
int main(void) {
    char license[LICENSE_BUFFER_SIZE] = {0};

    printf("Enterprise License Validator\n");
    printf("============================\n");
    printf("Enter License Key: ");
    
    if (read_license_key(license, sizeof(license)) != 0) {
        fprintf(stderr, "Error reading license key. Exiting.\n");
        return EXIT_FAILURE;
    }
    
    if (strlen(license) == 0) {
        fprintf(stderr, "No license key provided. Exiting.\n");
        return EXIT_FAILURE;
    }
    
    validate_license(license);
    
    return EXIT_SUCCESS;
}
