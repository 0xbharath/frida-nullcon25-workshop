// Frida script to hook C++ mangled "bodyHit" function in the nsnake binary
// This script is designed to be injected via Frida CLI and does not require any external "frida" module.

// Helper function to find the mangled symbol containing "bodyHit"
function findBodyHitSymbol(moduleName) {
    var symbols = Module.enumerateSymbolsSync(moduleName);
    for (var i = 0; i < symbols.length; i++) {
        var sym = symbols[i];
        if (sym.name.indexOf("bodyHit") !== -1) {
            console.log("Found candidate symbol: " + sym.name);
            return sym;
        }
    }
    return null;
}

var moduleName = "nsnake";
var targetSymbol = findBodyHitSymbol(moduleName);

if (targetSymbol !== null) {
    console.log("Hooking symbol: " + targetSymbol.name);
    Interceptor.attach(targetSymbol.address, {
        onEnter: function(args) {
            // Optionally log or modify arguments here if needed.
            console.log("bodyHit called");
        },
        onLeave: function(retval) {
            // Always return false (0) to ignore self-collision.
            console.log(targetSymbol.name + " returning false");
            retval.replace(0);
        }
    });
} else {
    console.log("No mangled symbol containing 'bodyHit' found in module " + moduleName);
}
