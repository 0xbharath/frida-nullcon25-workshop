// Find the address of "printf" in the target process
var printfPtr = Module.findExportByName(null, "printf");

Interceptor.attach(printfPtr, {
    onEnter: function (args) {
        // 1) Read the format string
        var formatString = Memory.readUtf8String(args[0]);
        if (!formatString) return; // If null or undefined, do nothing

        // 2) Check if it matches our known substring
        if (formatString.indexOf("The count is at:") !== -1) {
            // 3) On typical x86_64 or ARM, the next argument is the integer
            var currentCount = args[1].toInt32();

            // 4) Print the count value to Frida’s console
            console.log("[FRIDA] Current count is:", currentCount);
        }
    }
});
