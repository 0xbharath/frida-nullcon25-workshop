# Frida Exercise: Manipulating Writer Instructions

## What is this exercise?
This exercise demonstrates how to manipulate function execution dynamically using Frida's `Memory.patchCode` and writer utilities. We override the `calculate_damage` function in memory to return a random damage value instead of its original computation.

## Setup
To set up and compile the target binary, follow these steps:

```sh
# Compile the C program with necessary flags
gcc -Wall -Wextra -O2 -fno-stack-protector -no-pie -o battle battle.c
```

Run the compiled binary:

```sh
./battle
```

The program will pause for 5 seconds, allowing time to attach Frida.

## Explanation

### `battle.c`
This C program simulates a battle scenario where:
1. The player attacks with a base damage value.
2. The `calculate_damage` function doubles the base damage.
3. The program prints the calculated damage and a message hinting at possible manipulation.
4. A `sleep(5)` delay gives time to attach Frida.

### `frida_script.js`
The Frida script:
1. Locates the `calculate_damage` function in memory.
2. Generates a random damage value between 0 and 100.
3. Uses `Memory.patchCode` with `Arm64Writer` or `X86Writer` to replace the function’s return value.
4. Forces the function to return the random damage instead of performing its original calculation.

### Running Frida
Launch the program and attach Frida to the running process:

```sh
frida -p <pid> -l frida_script.js
```

Replace `<pid>` with the actual process ID of the running `battle` program. You can find the PID using:

```sh
pgrep battle
```

This ensures `calculate_damage` returns unpredictable values, creating a fun and chaotic battle system.

## Key Takeaways
- Learn how to locate functions in memory with Frida.
- Use `Memory.patchCode` to modify function behavior dynamically.
- Patch function return values using Frida’s writer utilities.

This exercise provides a hands-on introduction to real-time function modification in binaries using Frida!

