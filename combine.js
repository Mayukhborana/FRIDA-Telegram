console.log("🚀 WORKING COMBINED SEQUENCE");

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
            timestamp: new Date().toLocaleTimeString()
        };
        allCalls.push(entry);
        
        console.log("🔒 RECORDED: " + permission);
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
            allCalls.push({
                type: "NATIVE",
                name: module.name,
                timestamp: new Date().toLocaleTimeString()
            });
            console.log("🔧 RECORDED: " + module.name);
            loadedLibs[module.name] = true;
        }
    });
}

// Check every 3 seconds
setInterval(checkNative, 3000);

// DON'T auto-timeout - let user control when to stop
console.log("🎯 Recording STARTED!");
console.log("💡 Type 'showResults()' to see sequence anytime");
console.log("💡 Type 'stopRecording()' when done testing");

// Function to show results anytime
function showResults() {
    console.log("\n📊 CURRENT SEQUENCE:");
    if (allCalls.length === 0) {
        console.log("No calls recorded yet. Use Telegram features!");
    } else {
        allCalls.forEach(function(call, index) {
            if (call.type === "PERMISSION") {
                console.log((index + 1) + ". " + call.timestamp + " - PERMISSION: " + call.name + " - " + call.result);
            } else {
                console.log((index + 1) + ". " + call.timestamp + " - NATIVE: " + call.name);
            }
        });
    }
}

// Function to stop recording
function stopRecording() {
    console.log("\n🎉 FINAL SEQUENCE COLLECTED!");
    showResults();
}