console.log("🔒 COLLECTING PERMISSION SEQUENCE");

var permissionLog = [];

Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function(permission, pid, uid) {
        var result = this.checkPermission(permission, pid, uid);
        
        var entry = {
            time: new Date().toLocaleTimeString(),
            permission: permission,
            result: result === 0 ? "GRANTED" : "DENIED"
        };
        permissionLog.push(entry);
        
        console.log("📝 " + permission + " - " + entry.result);
        return result;
    };
});

// Print sequence after 30 seconds
setTimeout(function() {
    console.log("\n📋 PERMISSION CALL SEQUENCE:");
    permissionLog.forEach(function(entry, index) {
        console.log((index + 1) + ". " + entry.time + " - " + entry.permission + " - " + entry.result);
    });
}, 30000);

console.log("⏰ Recording permission sequence for 30 seconds...");