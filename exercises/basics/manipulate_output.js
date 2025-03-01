// Find the address of the "puts" export in the current process
var putsPtr = Module.findExportByName(null, "puts");

// Attach an interceptor to "puts"
Interceptor.attach(putsPtr, {
    onEnter: function (args) {
        // Read the original string from the first argument (char* s)
        var originalStr = Memory.readUtf8String(args[0]);
        
        // Check if the original string contains "Hello, World!"
        if (originalStr && originalStr.indexOf("Hello, World!") !== -1) {
            console.log("[+] Intercepted puts() with:", originalStr);
            
            // Prepare new string
            var newStr = "Hello, planet!"; // (puts will add the newline)
            
            // Allocate new string in memory and redirect the pointer
            args[0] = Memory.allocUtf8String(newStr);
            
            console.log("[+] Modified output to:", newStr);
        }
    }
});
