#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#define KEY_LENGTH 16
#define SECRET "EnterpriseSecret"

void simple_hash(const char *input, char *output) {
    unsigned int hash = 5381;
    int c;
    while ((c = *input++)) {
        hash = ((hash << 5) + hash) + c;
    }
    snprintf(output, KEY_LENGTH * 2 + 1, "%08x%08x", hash, hash >> 16);
}

int validate_key(const char *key) {
    char generated_hash[KEY_LENGTH * 2 + 1];
    simple_hash(SECRET, generated_hash);
    return strncmp(key, generated_hash, KEY_LENGTH * 2) == 0;
}

void grant_access() {
    printf("Access Granted! Enterprise features unlocked.\n");
}

int main() {
    char user_key[KEY_LENGTH * 2 + 1];
    
    printf("Enter your enterprise key: ");
    scanf("%32s", user_key);
    
    if (validate_key(user_key)) {
        grant_access();
    } else {
        printf("Invalid key. Access Denied.\n");
    }
    return 0;
}
