# Frida Memory Manipulation Exercise

## What is this Exercise?
This exercise demonstrates how to manipulate program execution and memory using Frida. We use Frida to patch function logic, scan memory for secrets, and dynamically allocate, copy, and duplicate memory buffers.

---

## Setup

### 1. Compile the C Program
Ensure you have GCC installed. Then, compile the C program:

```sh
gcc -o key_validator test.c
```

### 2. Run the Program
Execute the compiled binary:

```sh
./key_validator
```

It will prompt for an enterprise key. Entering the correct key grants access; otherwise, it denies entry.

### 3. Attach Frida to the Running Process

Use Frida to inject the script:

```sh
frida -p pid -l frida_script.js 
```

---

## Explanation

### 1. Patching `validate_key` to Always Return True
We locate the `validate_key` function in memory and modify its behavior so that it always returns `1`, effectively bypassing key validation.

- On **ARM32**, we replace it with:
  ```assembly
  mov r0, #1
  bx lr
  ```
- On **ARM64**, we replace it with:
  ```assembly
  mov w0, #1
  ret
  ```
- On **x86/x64**, we replace it with:
  ```assembly
  mov eax, 1
  ret
  ```

### 2. Scanning Memory for Secrets
We scan the program’s memory for two things:

- The hardcoded hash seed `5381` (used in the hashing function).
- The string `EnterpriseSecret` (used in key validation).

If found, this reveals where sensitive data is stored in memory.

### 3. Allocating and Manipulating Memory

- **Memory.alloc**: Allocates memory and writes data.
- **Memory.copy**: Copies data from one memory location to another.
- **Memory.dup**: Duplicates an existing memory region.

These techniques demonstrate how attackers or researchers can dynamically interact with program memory.

---

## Key Takeaways
- Frida enables real-time function patching to bypass checks.
- Memory scanning reveals hardcoded secrets.
- Memory allocation and manipulation demonstrate how programs store and process data dynamically.

This exercise highlights Frida’s power in analyzing and modifying applications at runtime!

