#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Prevent inlining so that Frida can find and patch the function.
__attribute__((noinline))
int calculate_damage(int base_damage) {
    // Original damage calculation: simply double the base damage.
    return base_damage * 2;
}

int main() {
    printf("Welcome to Battle of the Bytes!\n");
    printf("Get ready to attack... (you have 5 seconds to attach Frida for some hacking fun!)\n");
    
    // Pause to give you time to attach the Frida script.
    sleep(5);

    int base_damage = 5;
    int damage = calculate_damage(base_damage);
    printf("You attacked with base damage %d.\n", base_damage);
    printf("Calculated damage: %d\n", damage);
    printf("Was it a critical hit or a fluke? Only Frida knows!\n");

    return 0;
}
