# Frida Exercise: Register Manipulation

## What is this exercise?
This exercise demonstrates how to manipulate register values dynamically using Frida. By intercepting the `verify_manipulated` function, we alter the register holding the manipulated value to ensure license validation succeeds, regardless of input.

## Setup
To set up and compile the target binary, follow these steps:

```sh
# Compile the C program with necessary flags
cd ~/exercises/register
gcc -Wall -Wextra -O2 -fno-stack-protector -no-pie -o license_validator test.c
```

Run the compiled binary:

```sh
./license_validator
```

Enter any license key to see the validation process in action.

## Explanation

### `test.c`
This C program simulates an enterprise license validator that:
1. Computes a hash of the entered license key.
2. Applies obfuscation using XOR and subtraction.
3. Compares the result with an expected value (`0xDEADBEEF`).
4. Grants access only if the manipulated value matches the expected constant.

### `test.js`
The Frida script:
1. Locates the `verify_manipulated` function in memory.
2. Hooks into it using `Interceptor.attach()`.
3. Prints register values before the function executes.
4. Modifies the register holding the manipulated value (`x0` on ARM64, `RDI` on x86_64) to `0xDEADBEEF`, ensuring validation success.
5. Forces the function to always return success (`1`).

### Running Frida
Launch the program and inject Frida:

```sh
frida -p <PID> -s test.js
```

This ensures the license validation check always passes, demonstrating how Frida can be used to manipulate execution at runtime.

## Key Takeaways
- Learn how to find functions in memory using Frida.
- Manipulate register values dynamically.
- Override function return values to influence program behavior.

This exercise is a practical introduction to dynamic instrumentation and security testing using Frida.

