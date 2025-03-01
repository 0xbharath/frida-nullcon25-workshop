// snake_speed.js
// Frida script to modify the snake speed in the nSnake game by hooking Game::getDelay(int)

// Mangled name for Game::getDelay(int)
// (You may need to verify the mangled name using nm or another symbol dump tool)
var mangled_getDelay = "_ZN4Game8getDelayEi";

// Look up the address using DebugSymbol instead of Module.findExportByName,
// since non-exported C++ symbols often require symbol resolution via DebugSymbol.
var targetSymbol = DebugSymbol.fromName(mangled_getDelay);
if (targetSymbol === null) {
    console.log("Could not find symbol: " + mangled_getDelay);
} else {
    var targetAddr = targetSymbol.address;
    console.log("Attaching to getDelay at address: " + targetAddr);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            // In C++ member functions, args[0] is "this" pointer and args[1] is the integer argument.
            var originalArg = args[1].toInt32();
            console.log("Original speed argument: " + originalArg);

            // Modify the speed argument to make the snake move faster.
            // For example, reduce the delay by half.
            this.modifiedSpeed = originalArg / 2;
            console.log("Modified speed argument: " + this.modifiedSpeed);
        },
        onLeave: function(retval) {
            // Modify the return value (the delay) to our new value.
            // Since getDelay returns an int, we need to convert our number using ptr()
            // to satisfy Frida's type requirements.
            retval.replace(ptr(this.modifiedSpeed));
            console.log("New delay returned: " + retval.toInt32());
        }
    });
}
