"use strict";

console.log("🚀 Frida Fuzzing Adventure: Ready to hack the game...");

// Give the module a moment to load, then locate the target function.
setTimeout(() => {
    // Locate our target function in the process.
    var targetFunctionAddr = Module.findExportByName(null, "calculate_damage");
    if (targetFunctionAddr === null) {
        console.error("❌ calculate_damage not found! Ensure the program is compiled with symbols.");
        return;
    }
    console.log("🔍 Found calculate_damage at address: " + targetFunctionAddr);

    // Choose a random damage value between 0 and 100.
    var randomDamage = Math.floor(Math.random() * 101);
    console.log("🎲 Fuzz Mode Activated! Overriding damage to: " + randomDamage);

    // Patch the code in memory using the appropriate writer.
    Memory.patchCode(targetFunctionAddr, 0x20, function(code) {
        var writer;
        if (Process.arch === "arm64") {
            writer = new Arm64Writer(code, { pc: targetFunctionAddr });
            // In ARM64, the return value is in register x0.
            writer.putMovRegImm("x0", randomDamage);
            writer.putRet();
        } else if (Process.arch === "ia32" || Process.arch === "x64") {
            writer = new X86Writer(code, { pc: targetFunctionAddr });
            // For x86 architectures, return value is in eax (ia32) or rax (x64).
            if (Process.arch === "ia32") {
                writer.putMovRegImm("eax", randomDamage);
            } else {
                writer.putMovRegImm("rax", randomDamage);
            }
            writer.putRet();
        } else {
            console.error("❌ Unsupported architecture: " + Process.arch);
            return;
        }
        writer.flush();
        console.log("✅ calculate_damage successfully patched. Let the chaos begin!");
    });
}, 1000);
