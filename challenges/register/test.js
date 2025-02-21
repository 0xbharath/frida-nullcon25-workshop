// Locate the verify_manipulated function by its symbol.
var verifyAddr = Module.findExportByName(null, "verify_manipulated");
if (verifyAddr === null) {
    console.log("[-] Failed to locate verify_manipulated");
} else {
    console.log("[+] verify_manipulated found at: " + verifyAddr);

    // Helper function to print registers based on architecture.
    function printRegisters(context) {
        if (Process.arch === "arm64") {
            console.log("---- ARM64 Register Dump ----");
            console.log("x0:  " + context.x0);
            console.log("x1:  " + context.x1);
            console.log("x2:  " + context.x2);
            console.log("x3:  " + context.x3);
            console.log("x4:  " + context.x4);
            console.log("x5:  " + context.x5);
            console.log("x6:  " + context.x6);
            console.log("x7:  " + context.x7);
            console.log("x8:  " + context.x8);
            console.log("x9:  " + context.x9);
            console.log("x10: " + context.x10);
            console.log("x11: " + context.x11);
            console.log("x12: " + context.x12);
            console.log("x13: " + context.x13);
            console.log("x14: " + context.x14);
            console.log("x15: " + context.x15);
            console.log("x16: " + context.x16);
            console.log("x17: " + context.x17);
            console.log("x18: " + context.x18);
            console.log("x19: " + context.x19);
            console.log("x20: " + context.x20);
            console.log("x21: " + context.x21);
            console.log("x22: " + context.x22);
            console.log("x23: " + context.x23);
            console.log("x24: " + context.x24);
            console.log("x25: " + context.x25);
            console.log("x26: " + context.x26);
            console.log("x27: " + context.x27);
            console.log("x28: " + context.x28);
            console.log("fp:  " + context.fp);
            console.log("lr:  " + context.lr);
            console.log("sp:  " + context.sp);
            console.log("pc:  " + context.pc);
            console.log("----------------------------");
        } else {
            console.log("---- x86_64 Register Dump ----");
            console.log("RAX: " + context.rax);
            console.log("RBX: " + context.rbx);
            console.log("RCX: " + context.rcx);
            console.log("RDX: " + context.rdx);
            console.log("RSI: " + context.rsi);
            console.log("RDI: " + context.rdi);
            console.log("RBP: " + context.rbp);
            console.log("RSP: " + context.rsp);
            console.log("R8 : " + context.r8);
            console.log("R9 : " + context.r9);
            console.log("R10: " + context.r10);
            console.log("R11: " + context.r11);
            console.log("R12: " + context.r12);
            console.log("R13: " + context.r13);
            console.log("R14: " + context.r14);
            console.log("R15: " + context.r15);
            console.log("RIP: " + context.rip);
            console.log("------------------------------");
        }
    }

    Interceptor.attach(verifyAddr, {
        onEnter: function (args) {
            console.log("[*] Entering verify_manipulated()");

            // Dump the register values.
            printRegisters(this.context);

            if (Process.arch === "arm64") {
                // On ARM64, the first argument is in x0.
                console.log("[*] The manipulated value is passed in x0 on ARM64. Current x0: " + this.context.x0);
                console.log("[*] Overwriting x0 with 0xDEADBEEF (expected valid value).");
                this.context.x0 = ptr(0xDEADBEEF);
                console.log("[*] New x0: " + this.context.x0);
            } else {
                // On x86_64, the first argument is in RDI.
                console.log("[*] The manipulated value is passed in RDI on x86_64. Current RDI: " + this.context.rdi);
                console.log("[*] Overwriting RDI with 0xDEADBEEF (expected valid value).");
                this.context.rdi = ptr(0xDEADBEEF);
                console.log("[*] New RDI: " + this.context.rdi);
            }
        },
        onLeave: function (retval) {
            console.log("[*] Leaving verify_manipulated(), forcing return value to success (1).");
            retval.replace(1);
        }
    });
}
