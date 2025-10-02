console.log("🔒 Hooking Dangerous Permissions");

Java.perform(function() {
    // Dangerous permissions to monitor
    var dangerous = [
        "android.permission.READ_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", 
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_EXTERNAL_STORAGE"
    ];

    // Hook permission checks - FIXED: specify which overload to use
    var Activity = Java.use("android.app.Activity");
    
    // Use the common 3-parameter version
    Activity.checkPermission.overload('java.lang.String', 'int', 'int').implementation = function(permission, pid, uid) {
        var result = this.checkPermission(permission, pid, uid);
        
        if (dangerous.includes(permission)) {
            console.log("🚨 DANGEROUS PERMISSION: " + permission);
            console.log("   Result: " + (result === 0 ? "GRANTED" : "DENIED"));
            console.log("   Time: " + new Date().toLocaleTimeString());
        }
        
        return result;
    };

    console.log("✅ Ready! Monitoring " + dangerous.length + " dangerous permissions");
});