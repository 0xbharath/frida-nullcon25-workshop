// Attempt to locate the validate_key function.
var validateAddr = Module.findExportByName(null, "validate_key");
if (!validateAddr) {
    try {
        validateAddr = DebugSymbol.fromName("validate_key").address;
    } catch (e) {
        console.log("validate_key not found via DebugSymbol: " + e);
    }
}

if (validateAddr) {
    console.log("Found validate_key at: " + validateAddr);
    // Change memory protection to allow patching.
    Memory.protect(validateAddr, 16, 'rwx');

    if (Process.arch === "arm") {
        // ARM32 patch: mov r0, #1; bx lr
        Memory.patchCode(validateAddr, 8, function(code) {
            var writer = new ArmWriter(code, { pc: validateAddr });
            writer.putMovRegImm('r0', 1);
            writer.putBranchReg('lr');
            writer.flush();
        });
        console.log("Patched ARM32 validate_key to always return 1.");
    } else if (Process.arch === "arm64") {
        // ARM64 patch using hard-coded opcodes:
        // 0x52800001 -> mov w0, #1 ; 0xD65F03C0 -> ret
        Memory.patchCode(validateAddr, 8, function(code) {
            var writer = new Arm64Writer(code, { pc: validateAddr });
            writer.putInstruction(0x52800001); // mov w0, #1
            writer.putInstruction(0xD65F03C0);   // ret
            writer.flush();
        });
        console.log("Patched ARM64 validate_key to always return 1.");
    } else if (Process.arch === "ia32" || Process.arch === "x64") {
        // x86/x64 patch: mov eax, 1; ret
        Memory.patchCode(validateAddr, 6, function(code) {
            var writer = new X86Writer(code, { pc: validateAddr });
            writer.putMovRegImm('eax', 1);
            writer.putRet();
            writer.flush();
        });
        console.log("Patched x86/x64 validate_key to always return 1.");
    } else {
        console.log("Unsupported architecture: " + Process.arch);
    }
} else {
    console.log("validate_key not found.");
}

// Retrieve the main module.
var mainModule = Process.enumerateModules()[0];
console.log("Main module: " + mainModule.name + " at " + mainModule.base + " (size: " + mainModule.size + ")");

// Enumerate accessible (r-x) memory ranges in the main module.
var ranges = Process.enumerateRangesSync({
    protection: 'r-x',
    module: mainModule.name
});

if (ranges.length > 0) {
    var range = ranges[0];
    console.log("Using memory range for scanning: " + range.base + " - " + (range.base.add(range.size)));
    
    // 1. Asynchronous Memory.scan for the hex pattern "35 33 38 31" (ASCII "5381").
    Memory.scan(range.base, range.size, "35 33 38 31", {
        onMatch: function(address, size) {
            console.log("Async scan: Found possible hash seed at: " + address);
        },
        onComplete: function() {
            console.log("Async memory scan complete.");
        }
    });
    
    // 2. Synchronous Memory.scanSync for the hex pattern of "EnterpriseSecret".
    try {
        var results = Memory.scanSync(range.base, range.size,
            "45 6e 74 65 72 70 72 69 73 65 53 65 63 72 65 74");
        results.forEach(function(result) {
            console.log("Sync scan: Found 'EnterpriseSecret' at: " + result.address);
        });
    } catch (e) {
        console.log("Memory.scanSync error: " + e);
    }
} else {
    console.log("No readable memory range found for scanning in module " + mainModule.name);
}

// Demonstrate additional Memory APIs.
// 3. Memory.alloc: Allocate memory and write a string.
var allocBuffer = Memory.alloc(32);
Memory.writeUtf8String(allocBuffer, "Allocated Buffer Data");
console.log("Allocated memory at: " + allocBuffer +
            " with data: " + Memory.readUtf8String(allocBuffer));

// 4. Memory.copy: Copy data from allocBuffer to a new buffer.
var copyBuffer = Memory.alloc(32);
Memory.copy(copyBuffer, allocBuffer, 32);
console.log("Copied data to new buffer at: " + copyBuffer +
            " with data: " + Memory.readUtf8String(copyBuffer));

// 5. Memory.dup: Duplicate the memory region of allocBuffer.
var dupBuffer = Memory.dup(allocBuffer, 32);
console.log("Duplicated memory at: " + dupBuffer +
            " with data: " + Memory.readUtf8String(dupBuffer));
