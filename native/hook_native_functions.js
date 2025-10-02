console.log("🔧 NATIVE HOOKS THAT ALWAYS WORK");

// Just monitor when native libraries are loaded
var loadedModules = {};

setInterval(function() {
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        if (!loadedModules[module.name] && module.name.includes('tmessages')) {
            console.log("🎯 NATIVE LIBRARY LOADED: " + module.name);
            console.log("   Base: " + module.base);
            console.log("   Size: " + module.size);
            loadedModules[module.name] = true;
        }
    });
}, 2000);

// Monitor thread creation for native activity
var threadCount = Process.enumerateThreads().length;

setInterval(function() {
    var newThreadCount = Process.enumerateThreads().length;
    if (newThreadCount > threadCount) {
        console.log("🔧 NATIVE ACTIVITY: New thread created");
        threadCount = newThreadCount;
    }
}, 1000);

console.log("✅ Monitoring for native library loading and thread creation...");
console.log("📱 Use Telegram - when you see 'NATIVE LIBRARY LOADED', native code is running!");