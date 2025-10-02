console.log("🚀 JSONL COMBINED SEQUENCE RECORDER");

var allCalls = [];

Java.perform(function() {
    // Hook permissions
    var Activity = Java.use("android.app.Activity");
    Activity.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function(permission, pid, uid) {
        var result = this.checkPermission(permission, pid, uid);
        
        var entry = {
            type: "PERMISSION",
            name: permission,
            result: result === 0 ? "GRANTED" : "DENIED",
            timestamp: new Date().toISOString(),
            pid: pid,
            uid: uid
        };
        allCalls.push(entry);
        
        // Print JSONL to console
        console.log(JSON.stringify(entry));
        return result;
    };
    console.log("✅ Permission hook ACTIVE");
});

// Track native libraries
var loadedLibs = {};
function checkNative() {
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        if (!loadedLibs[module.name] && module.name.includes('tmessages')) {
            var entry = {
                type: "NATIVE_LIB",
                name: module.name,
                base: module.base.toString(),
                size: module.size,
                path: module.path,
                timestamp: new Date().toISOString()
            };
            allCalls.push(entry);
            loadedLibs[module.name] = true;
            
            // Print JSONL to console
            console.log(JSON.stringify(entry));
        }
    });
}

// Check every 3 seconds
setInterval(checkNative, 3000);

// Function to show results
function showResults() {
    console.log("\n📊 CURRENT SEQUENCE (" + allCalls.length + " entries):");
    allCalls.forEach(function(call, index) {
        if (call.type === "PERMISSION") {
            console.log((index + 1) + ". " + call.timestamp + " - PERMISSION: " + call.name + " - " + call.result);
        } else {
            console.log((index + 1) + ". " + call.timestamp + " - NATIVE: " + call.name);
        }
    });
}

// Function to export all data as JSONL
function exportJSONL() {
    console.log("\n💾 EXPORTING ALL DATA AS JSONL:");
    allCalls.forEach(function(call) {
        console.log(JSON.stringify(call));
    });
    console.log("✅ Exported " + allCalls.length + " entries");
}

console.log("🎯 JSONL Recording STARTED!");
console.log("💡 Type 'showResults()' to see sequence");
console.log("💡 Type 'exportJSONL()' to export all data");
console.log("💡 Type 'stopRecording()' to show final results");

function stopRecording() {
    exportJSONL();
    showResults();
    console.log("🎉 RECORDING COMPLETE!");
}