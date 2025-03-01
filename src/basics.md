# Basic Instrumentation with Frida

# FRida 101

1. Go to the directory `~/exercises/basics/`

```bash
cd ~/exercises/basics
```

2. There is a binary named `hello_world.c`

***What is this Binary?**

## Inspect the binary file

_Run the following commands in docker container___ Running the Binary and understanding the output

```bash
gcc hello_world.c -o hw
file hw
```

- Execute the binary and understand the output

```bash
./hw
Hello, World!
```

**Question 1: How does this binary print the text?**

**Question 2: Can we manipulate the binary to print different output?**
  
## Instrumenting the binary using Frida 

_ Run the following command to spawn the binary using Frida_

```bash
$ frida ./hw --pause
... SNIPPED ...
   . . . .   Connected to Local System (id=local)
Spawned `./helloword.o`. Use %resume to let the main thread start executing!
[Local::helloword.o ]->
```

## Dig deeper into binary

_Run the following command to enumerate the modules/functions invoked by the binary_


You can run the following JS code in the Frida REPL after hooking into the process

```
Process.enumerateModules().forEach(m => console.log(m.name));
```

You can save this into a file and run this after attaching/spawning a binary

```js
// save this as enumerate.js
var modules = Process.enumerateModules()

Process.enumerateModules()[0]
  for (var i = 0; i < modules.length; i++) {
  console.log("module name: " + modules[i].name); 
}
```

```bash
frida ./hw -l enumerate.js
```

- Lets print all the imports and exports which are present in out binary

```js
      //We can explore the binary a little, by enumerating function names from imports, getting addresses from debug symbols (won’t work on stripped             binaries, obviously), disassemble an instruction at an address.

      Module.enumerateImportsSync('hw').forEach( function (elem) { console.log(elem['name']); });
      DebugSymbol.fromName('printf')
      

      //Use interceptor to confirm the usage of printf
      Interceptor.attach(Module.findExportByName(null,'printf'),
      {
        onEnter: function(args)
      {
        console.log("enter")
      },
        onLeave: function(args)
      {
        console.log("leave")
      }})


      //Let's change the text 
      Interceptor.attach(Module.findExportByName(null, 'printf'), {
        onEnter: function(args) {
        console.log("printf: " + args[0].readCString());
        console.log("change the string")
        Memory.protect(args[0], 15, "rwx");
        args[0].writeUtf8String("Hello Frida");
        console.log("printf: " + args[0].readCString());
        } 
        });
```

Let's manipulate the output of the binary

```js
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
            var newStr = "Hello, Planet!"; // (puts will add the newline)
            
            // Allocate new string in memory and redirect the pointer
            args[0] = Memory.allocUtf8String(newStr);
            
            console.log("[+] Modified output to:", newStr);
        }
    }
});
```