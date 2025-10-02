console.log("🔍 Finding Native Library");

Java.perform(function() {
    // List all loaded modules
    var modules = Process.enumerateModules();
    
    console.log("📚 Loaded Native Libraries:");
    modules.forEach(function(module) {
        // Look for Telegram libraries
        if (module.name.includes('tmessages') || module.name.includes('tg')) {
            console.log("🎯 FOUND TELEGRAM LIBRARY: " + module.name);
            console.log("   Path: " + module.path);
            console.log("   Base: " + module.base);
            console.log("   Size: " + module.size);
        }
    });
});