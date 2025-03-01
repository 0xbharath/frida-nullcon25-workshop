// Frida script to hook Board::isWall and Board::isBorder in nsnake
// This script forces both functions to always return false,
// preventing the game from triggering a game over due to wall collisions.

function findSymbol(moduleName, searchString) {
    var symbols = Module.enumerateSymbolsSync(moduleName);
    for (var i = 0; i < symbols.length; i++) {
        var sym = symbols[i];
        if (sym.name.indexOf(searchString) !== -1) {
            console.log("Found candidate symbol for " + searchString + ": " + sym.name);
            return sym;
        }
    }
    return null;
}

var moduleName = "nsnake";

// Hook Board::isWall
var isWallSymbol = findSymbol(moduleName, "isWall");
if (isWallSymbol !== null) {
    console.log("Hooking symbol for isWall: " + isWallSymbol.name);
    Interceptor.attach(isWallSymbol.address, {
        onEnter: function(args) {
            // Log the coordinates being checked
            console.log("isWall called with: x = " + args[1].toInt32() + ", y = " + args[2].toInt32());
        },
        onLeave: function(retval) {
            console.log(isWallSymbol.name + " returning false");
            retval.replace(0);
        }
    });
} else {
    console.log("No symbol found for 'isWall'");
}

// Hook Board::isBorder in case the game uses border detection to end the game
var isBorderSymbol = findSymbol(moduleName, "isBorder");
if (isBorderSymbol !== null) {
    console.log("Hooking symbol for isBorder: " + isBorderSymbol.name);
    Interceptor.attach(isBorderSymbol.address, {
        onEnter: function(args) {
            // Log the coordinates being checked
            console.log("isBorder called with: x = " + args[1].toInt32() + ", y = " + args[2].toInt32());
        },
        onLeave: function(retval) {
            console.log(isBorderSymbol.name + " returning false");
            retval.replace(0);
        }
    });
} else {
    console.log("No symbol found for 'isBorder'");
}
