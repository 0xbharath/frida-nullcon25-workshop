// Frida script to hook the C++ mangled "isWall" function in nsnake
// This script is designed to be loaded via the Frida CLI and will force the isWall function to always return false,
// effectively preventing wall collision detection.

function findIsWallSymbol(moduleName) {
    const symbols = Module.enumerateSymbolsSync(moduleName);
    for (let i = 0; i < symbols.length; i++) {
        const sym = symbols[i];
        if (sym.name.indexOf("isWall") !== -1) {
            console.log("Found candidate symbol: " + sym.name);
            return sym;
        }
    }
    return null;
}

const moduleName = "nsnake";
const targetSymbol = findIsWallSymbol(moduleName);

if (targetSymbol !== null) {
    console.log("Hooking symbol: " + targetSymbol.name);
    Interceptor.attach(targetSymbol.address, {
        onEnter: function(args) {
            // Optionally, log the head coordinates being checked.
            console.log("isWall called with: x = " + args[1].toInt32() + ", y = " + args[2].toInt32());
        },
        onLeave: function(retval) {
            // Always return false (0) to ignore wall collisions.
            console.log(targetSymbol.name + " returning false");
            retval.replace(0);
        }
    });
} else {
    console.log("No mangled symbol containing 'isWall' found in module " + moduleName);
}
