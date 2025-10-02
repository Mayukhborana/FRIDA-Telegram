console.log("Starting Telegram hook for Frida 17.3.2...");

function hookTelegram() {
    var modules = Process.enumerateModules();
    console.log("Total modules: " + modules.length);
    
    modules.forEach(function(module) {
        // Look for Telegram libraries
        if (module.name.indexOf('tmessages') !== -1 || 
            module.name.indexOf('tg') !== -1 || 
            module.name.indexOf('telegram') !== -1) {
            
            console.log("\n*** Found Telegram module: " + module.name + " ***");
            console.log("Base: " + module.base);
            console.log("Size: " + module.size);
            console.log("Path: " + module.path);
            
            exploreModule(module.name);
        }
    });
}

function exploreModule(moduleName) {
    console.log("\nExploring module: " + moduleName);
    
    try {
        // Get exports
        var exports = Module.enumerateExports(moduleName);
        console.log("Total exports: " + exports.length);
        
        // Show first 30 exports
        console.log("First 30 exports:");
        for (var i = 0; i < Math.min(30, exports.length); i++) {
            var exp = exports[i];
            console.log("  " + i + ": " + exp.name + " @ " + exp.address);
        }
        
        // Look for interesting functions
        console.log("\nLooking for interesting functions...");
        var interesting = exports.filter(function(exp) {
            var name = exp.name.toLowerCase();
            return name.indexOf('encrypt') !== -1 || 
                   name.indexOf('decrypt') !== -1 ||
                   name.indexOf('send') !== -1 ||
                   name.indexOf('receive') !== -1 ||
                   name.indexOf('message') !== -1 ||
                   name.indexOf('chat') !== -1 ||
                   name.indexOf('auth') !== -1 ||
                   name.indexOf('key') !== -1;
        });
        
        console.log("Found " + interesting.length + " interesting functions:");
        interesting.forEach(function(func, idx) {
            console.log("  " + idx + ": " + func.name + " @ " + func.address);
        });
        
    } catch(e) {
        console.log("Error exploring module: " + e);
        console.log("Stack: " + e.stack);
    }
}

// Start hooking
hookTelegram();