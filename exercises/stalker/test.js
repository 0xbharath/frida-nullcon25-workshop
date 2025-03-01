// Configure Stalker parameters
Stalker.trustThreshold = 1;
Stalker.queueCapacity = 16384; // default capacity
Stalker.queueDrainInterval = 250; // drain every 250ms

// Optionally exclude a range from a module (e.g. a section of libc) to focus on our custom code.
var libcBase = Module.findBaseAddress('libc.so.6');
if (libcBase) {
    var excludeRangeStart = libcBase;
    var excludeRangeEnd = libcBase.add(0x1000);
    console.log("[*] Excluding libc range from Stalker: " + excludeRangeStart + " - " + excludeRangeEnd);
    Stalker.exclude(excludeRangeStart, excludeRangeEnd);
}

// Locate the target function 'process_input' in our binary.
const targetFunction = Module.findExportByName(null, "process_input");
if (!targetFunction) {
    console.error("Error: 'process_input' not found. Make sure the binary is compiled with symbols.");
} else {
    console.log("[*] Hooking process_input at: " + targetFunction);

    // Global counter for call instructions
    var callCounter = 0;

    // Add a call probe to log each time the function is called.
    var callProbeId = Stalker.addCallProbe(targetFunction, function (context) {
        console.log("[*] Call probe triggered at:", this.address, " with context:", context);
    });

    // Attach an interceptor to process_input to monitor its execution.
    Interceptor.attach(targetFunction, {
        onEnter: function (args) {
            console.log("====================================================");
            console.log("[*] process_input() called");
            console.log("[*] Input argument:", Memory.readUtf8String(args[0]));
            
            // Flush any pending Stalker events.
            Stalker.flush();
            
            // Start following the current thread using Stalker.
            Stalker.follow(this.threadId, {
                events: { call: true, ret: true, exec: true, block: true },
                transform: function (iterator) {
                    let instruction;
                    while ((instruction = iterator.next()) !== null) {
                        // Log each instruction address and disassembly.
                        console.log("[*] Instruction at:", instruction.address, instruction.toString());
                        
                        // If a call instruction is encountered, increment our counter.
                        if (instruction.mnemonic && instruction.mnemonic.indexOf("call") !== -1) {
                            callCounter++;
                            console.log("[+] Call instruction encountered at:", instruction.address);
                        }
                        
                        // Demonstrate Transformer: randomly NOP out (replace with no-ops) some instructions.
                        if (Math.random() < 0.1) {
                            console.log("[!] Attempting to NOP instruction at:", instruction.address);
                            if (typeof instruction.putNop === 'function') {
                                instruction.putNop();
                            } else {
                                console.warn("[!] instruction.putNop is not a function at:", instruction.address);
                            }
                        }
                        
                        // Ensure we keep the current instruction in the output stream.
                        if (typeof iterator.keep === 'function') {
                            iterator.keep();
                        } else {
                            console.warn("[!] iterator.keep is not a function");
                        }
                    }
                },
                onReceive: function (events) {
                    console.log("[*] Received Stalker events (raw data length):", events.byteLength);
                    // Parse events and log call summaries.
                    Stalker.parse(events, {
                        onCallSummary: function (summary) {
                            console.log("[*] Call Summary:\n" + JSON.stringify(summary, null, 2));
                        }
                    });
                }
            });
        },
        onLeave: function (retval) {
            console.log("[*] process_input() finished");
            console.log("[*] Return Value:", retval);
            console.log("[*] Total call instructions encountered: " + callCounter);
            
            // Flush and stop following the thread to clean up.
            Stalker.flush();
            Stalker.unfollow(this.threadId);
            
            // Remove the call probe.
            Stalker.removeCallProbe(callProbeId);
            
            // Garbage collect any accumulated memory in the Stalker queue.
            Stalker.garbageCollect();
            console.log("====================================================");
        }
    });
}
