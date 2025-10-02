
console.log("=== Minimal Native Hook for Telegram ===");

function setupNativeHooks() {
    console.log("1. Finding Telegram native module...");
    
    var telegramModule = Process.findModuleByName("libtmessages.49.so");
    if (!telegramModule) {
        console.log("❌ Telegram module not found!");
        return;
    }
    
    console.log("✅ Found: " + telegramModule.name);
    console.log("   Base: " + telegramModule.base);
    console.log("   Size: " + telegramModule.size);
    
    console.log("\n2. Setting up basic hooks...");
    
    // Hook using Memory.scan to find and hook functions
    scanAndHookFunctions(telegramModule);
    
    console.log("\n3. Setting up generic trace...");
    setupGenericTracer();
    
    console.log("✅ Ready! Use Telegram and watch for native calls...");
}

function scanAndHookFunctions(module) {
    console.log("Scanning module for function patterns...");
    
    // We'll hook by scanning for common patterns or using known offsets
    try {
        // Method 1: Hook entry points by scanning for common patterns
        var patterns = [
            "F0 47 BD A9", // Common ARM64 function prologue
            "FF 83 00 D1", // Another common prologue
            "FD 7B BF A9"  // Another function pattern
        ];
        
        for (var i = 0; i < patterns.length; i++) {
            try {
                Memory.scan(module.base, module.size, patterns[i], {
                    onMatch: function(address, size) {
                        console.log("🔍 Found potential function at: " + address);
                        hookAddress(address, "unknown_function_" + address);
                    },
                    onError: function(reason) {
                        // Continue scanning
                    },
                    onComplete: function() {
                        // Scanning completed
                    }
                });
            } catch(e) {
                // Pattern not found, continue
            }
        }
        
    } catch(e) {
        console.log("Scanning failed: " + e);
    }
}

function hookAddress(address, name) {
    try {
        Interceptor.attach(address, {
            onEnter: function(args) {
                console.log("\n🎯 NATIVE CALL: " + name);
                console.log("   Address: " + address);
                console.log("   Thread: " + Process.getCurrentThreadId());
                console.log("   Time: " + Date.now());
                
                // Log backtrace
                try {
                    console.log("   Backtrace:");
                    var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                    for (var i = 0; i < Math.min(3, backtrace.length); i++) {
                        console.log("     " + backtrace[i]);
                    }
                } catch(e) {
                    // Backtrace might fail
                }
                
                this.startTime = Date.now();
            },
            onLeave: function(retval) {
                var duration = Date.now() - this.startTime;
                console.log("   ✅ " + name + " completed in " + duration + "ms");
            }
        });
        console.log("✅ Hooked: " + name);
    } catch(e) {
        console.log("❌ Failed to hook " + name + ": " + e);
    }
}

function setupGenericTracer() {
    console.log("Setting up system call tracer...");
    
    // Hook some system functions that Telegram definitely uses
    var systemFunctions = [
        // These are common functions that should exist
        "open", "read", "write", "close", "socket", "connect"
    ];
    
    for (var i = 0; i < systemFunctions.length; i++) {
        var funcName = systemFunctions[i];
        try {
            // Try to find in libc
            var address = Module.findExportByName("libc.so", funcName);
            if (address) {
                Interceptor.attach(address, {
                    onEnter: function(args) {
                        console.log("📞 SYS CALL: " + this.funcName);
                    },
                    onLeave: function(retval) {
                        // Do nothing
                    }
                });
                // Store function name
                Interceptor.attach(address, {
                    funcName: funcName
                });
                console.log("✅ System hook: " + funcName);
            }
        } catch(e) {
            console.log("❌ Failed system hook for " + funcName);
        }
    }
}

// Start the hooks
setupNativeHooks();